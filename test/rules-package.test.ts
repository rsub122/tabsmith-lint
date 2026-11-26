import { describe, it, expect } from "vitest";
import { buildZip, withArchive, type ZipEntryInput } from "./zip-writer.js";
import { analyzeInput } from "../src/engine/analyze.js";
import { analyzeExt } from "./tmp-ext.js";
import { packageRules, PACKAGE_LIMIT_BYTES } from "../src/rules/package.js";
import type { ExtensionModel, Finding } from "../src/engine/model.js";

const MANIFEST = { manifest_version: 3, name: "P", version: "1.0.0", background: { service_worker: "bg.js" } };

function lintZip(extra: ZipEntryInput[], manifest: object = MANIFEST) {
  const zip = buildZip([{ name: "manifest.json", data: manifest }, { name: "bg.js", data: "console.log(1)" }, ...extra]);
  return withArchive(zip, ".zip", (p) => analyzeInput(p, { version: "t" }).browsers.chrome);
}
const pkg = (r: { findings: Finding[] }, id = "PKG001") => r.findings.filter((f) => f.ruleId === id);

describe("PKG001: files that should not ship (archive input)", () => {
  it("clean package → no PKG findings, verdict pass", () => {
    const r = lintZip([{ name: "icons/128.png", data: Buffer.alloc(10) }, { name: "_locales/en/messages.json", data: {} }]);
    expect(r.findings.filter((f) => f.ruleId.startsWith("PKG"))).toEqual([]);
    expect(r.verdict).toBe("pass");
  });

  it(".env / .env.production → fix, names the files, mentions secrets", () => {
    const f = pkg(lintZip([{ name: ".env", data: "API_KEY=x" }, { name: "config/.env.production", data: "A=1" }]));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].message).toMatch(/2 file\(s\): \.env, config\/\.env\.production/);
    expect(f[0].message).toMatch(/secret/);
  });

  it("private key (.pem) → fix", () => {
    const f = pkg(lintZip([{ name: "key.pem", data: "placeholder, not a real key" }]));
    expect(f.map((x) => [x.severity, x.title])).toEqual([["fix", "Private key (.pem) in the package"]]);
  });

  it(".git/ → fix; .gitignore and .github/ are not VCS metadata", () => {
    const f = pkg(lintZip([{ name: ".git/HEAD", data: "ref" }, { name: ".git/objects/ab/cd", data: "x" }]));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].message).toMatch(/^2 file/);
    expect(pkg(lintZip([{ name: ".gitignore", data: "x" }, { name: ".github/workflows/ci.yml", data: "x" }]))).toEqual([]);
  });

  it("node_modules/ → fix, and its code is not scanned (no OBF/MV3 noise from deps)", () => {
    const r = lintZip([
      { name: "node_modules/lodash/lodash.js", data: "eval('1')" },
      { name: "node_modules/lodash/package.json", data: {} },
    ]);
    const f = pkg(r);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].title).toMatch(/node_modules/);
    expect(r.findings.some((x) => x.ruleId === "MV3002")).toBe(false);
  });

  it("node_modules file the manifest loads → info only, and names the referenced file", () => {
    const m = { ...MANIFEST, background: { service_worker: "bg.js" }, content_scripts: [{ matches: ["https://example.com/*"], js: ["node_modules/webextension-polyfill/dist/browser-polyfill.js"] }] };
    const f = pkg(lintZip([
      { name: "node_modules/webextension-polyfill/dist/browser-polyfill.js", data: "1" },
      { name: "node_modules/webextension-polyfill/README.md", data: "x" },
    ], m));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].message).toMatch(/referenced file\(s\) there are loaded by the extension \(node_modules\/webextension-polyfill\/dist\/browser-polyfill\.js\)/);
    expect(f[0].message).toMatch(/^1 file\(s\): node_modules\/webextension-polyfill\/README\.md/);
  });

  it("source maps → info (allowed, but they publish your source)", () => {
    const f = pkg(lintZip([{ name: "bg.js.map", data: "{}" }]));
    expect(f.map((x) => x.severity)).toEqual(["info"]);
    expect(f[0].title).toMatch(/Source maps/);
  });

  it("tests → info; look-alike names are not tests", () => {
    const f = pkg(lintZip([{ name: "tests/a.js", data: "1" }, { name: "src/util.spec.ts", data: "1" }, { name: "__tests__/b.test.js", data: "1" }]));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].message).toMatch(/^3 file/);
    expect(pkg(lintZip([{ name: "contest/a.js", data: "1" }, { name: "latest.json", data: {} }, { name: "testing-utils.js", data: "1" }, { name: "attest.js", data: "1" }, { name: "cm/mode/rpm/spec/spec.js", data: "1" }]))).toEqual([]);
  });

  it("OS junk (.DS_Store, __MACOSX/, Thumbs.db) → info", () => {
    const f = pkg(lintZip([{ name: ".DS_Store", data: "x" }, { name: "__MACOSX/._bg.js", data: "x" }, { name: "img/Thumbs.db", data: "x" }]));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].message).toMatch(/^3 file/);
  });

  it("a file counts once (first matching category): a test file under node_modules is reported as node_modules only", () => {
    const f = pkg(lintZip([{ name: "node_modules/x/test/a.js", data: "1" }]));
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/node_modules/);
  });

  it("long lists are truncated with a count", () => {
    const many = Array.from({ length: 9 }, (_, i) => ({ name: `m${i}.js.map`, data: "{}" }));
    expect(pkg(lintZip(many))[0].message).toMatch(/\(\+4 more\)/);
  });

  it("does NOT run on directory input (a source folder normally has node_modules/.git/tests)", () => {
    const r = analyzeExt({
      "manifest.json": MANIFEST,
      "bg.js": "1",
      ".env": "A=1",
      "node_modules/x/index.js": "1",
      "tests/a.test.js": "1",
      "bg.js.map": "{}",
    });
    expect(pkg(r)).toEqual([]);
    expect(pkg(r, "PKG003")).toEqual([]);
  });

  it("fix-level PKG001 makes the verdict needs_fixes; info-only keeps pass", () => {
    expect(lintZip([{ name: ".env", data: "A=1" }]).verdict).toBe("needs_fixes");
    expect(lintZip([{ name: "bg.js.map", data: "{}" }]).verdict).toBe("pass");
  });
});

describe("PKG002: \"key\" in manifest.json", () => {
  it("info on archive input, with a manifest line", () => {
    const f = pkg(lintZip([], { ...MANIFEST, key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" }), "PKG002");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].file).toBe("manifest.json");
    expect(f[0].line).toBeGreaterThan(0);
  });

  it("info on directory input too; absent key → nothing", () => {
    expect(pkg(analyzeExt({ "manifest.json": { ...MANIFEST, key: "abc" }, "bg.js": "1" }), "PKG002")).toHaveLength(1);
    expect(pkg(analyzeExt({ "manifest.json": MANIFEST, "bg.js": "1" }), "PKG002")).toEqual([]);
  });

  it("a nested \"key\" (e.g. inside commands) is not the top-level field", () => {
    const m = { ...MANIFEST, commands: { go: { suggested_key: { default: "Ctrl+Shift+Y" } } } };
    expect(pkg(analyzeExt({ "manifest.json": m, "bg.js": "1" }), "PKG002")).toEqual([]);
  });
});

describe("PKG003: 2 GB package limit", () => {
  const model = (archiveBytes: number) =>
    ({ manifest: MANIFEST, manifestRaw: "{}", manifestRefs: [], files: [], package: { kind: "zip", archiveBytes, files: [], unsafePaths: [] } }) as unknown as ExtensionModel;
  const run = (bytes: number) => packageRules.flatMap((r) => r(model(bytes))).filter((f) => f.ruleId === "PKG003");

  it("over 2 GiB → reject", () => {
    const f = run(PACKAGE_LIMIT_BYTES + 1);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("reject");
    expect(f[0].message).toMatch(/2GB/);
  });
  it("within 10% of the limit → info; exactly at the limit is not over", () => {
    expect(run(PACKAGE_LIMIT_BYTES).map((f) => f.severity)).toEqual(["info"]);
    expect(run(Math.floor(PACKAGE_LIMIT_BYTES * 0.95)).map((f) => f.severity)).toEqual(["info"]);
  });
  it("normal sizes → nothing", () => {
    expect(run(50 * 1024 * 1024)).toEqual([]);
    expect(run(Math.floor(PACKAGE_LIMIT_BYTES * 0.89))).toEqual([]);
  });
  it("no package (directory input) → nothing", () => {
    const m = { ...model(0), package: undefined } as ExtensionModel;
    expect(packageRules.flatMap((r) => r(m))).toEqual([]);
  });
});
