import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildZip, withArchive, type ZipEntryInput } from "./zip-writer.js";
import { listArchive, extractArchive, safeEntryPath, isArchivePath } from "../src/engine/archive.js";
import { analyze, analyzeInput } from "../src/engine/analyze.js";
import { ManifestError } from "../src/engine/manifest.js";
import { run } from "../src/cli.js";
import { fixtureDir, ruleIds } from "./helpers.js";

/** Zip every file of a fixture directory (paths relative to it). */
function fixtureEntries(name: string, opts: { store?: boolean } = {}): ZipEntryInput[] {
  const root = fixtureDir(name);
  const out: ZipEntryInput[] = [];
  (function rec(dir: string, prefix: string) {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.isDirectory()) rec(join(dir, e.name), rel);
      else out.push({ name: rel, data: readFileSync(join(dir, e.name)), store: opts.store });
    }
  })(root, "");
  return out;
}

const nonPkg = (ids: string[]) => ids.filter((id) => !id.startsWith("PKG")).sort();

const MANIFEST = { manifest_version: 3, name: "Z", version: "1.0.0", background: { service_worker: "bg.js" } };

describe("archive reader", () => {
  it("isArchivePath recognizes .zip/.crx case-insensitively", () => {
    expect(isArchivePath("a/ext.zip")).toBe(true);
    expect(isArchivePath("EXT.CRX")).toBe(true);
    expect(isArchivePath("ext")).toBe(false);
    expect(isArchivePath("ext.zip.txt")).toBe(false);
  });

  it("safeEntryPath normalizes and refuses paths that escape the root", () => {
    expect(safeEntryPath("a/./b.js")).toBe("a/b.js");
    expect(safeEntryPath("a\\b.js")).toBe("a/b.js");
    expect(safeEntryPath("../evil.js")).toBeNull();
    expect(safeEntryPath("a/../../evil.js")).toBeNull();
    expect(safeEntryPath("/etc/passwd")).toBeNull();
    expect(safeEntryPath("C:/x.js")).toBeNull();
  });

  it("lists stored + deflated entries with sizes and skips directory entries", () => {
    const zip = buildZip([
      { name: "manifest.json", data: MANIFEST },
      { name: "img/", data: "" },
      { name: "img/icon.png", data: Buffer.alloc(300, 1), store: true },
    ]);
    withArchive(zip, ".zip", (p) => {
      const l = listArchive(p);
      expect(l.kind).toBe("zip");
      expect(l.entries.map((e) => e.relPath).sort()).toEqual(["img/icon.png", "manifest.json"]);
      expect(l.entries.find((e) => e.relPath === "img/icon.png")!.size).toBe(300);
      expect(l.fileSize).toBe(zip.length);
    });
  });

  it("extracts code/JSON content exactly (deflate and stored); binaries become empty placeholders", () => {
    const js = "const x = 1;\n".repeat(500) + "// ünïcödé";
    const zip = buildZip([
      { name: "manifest.json", data: MANIFEST },
      { name: "bg.js", data: js },
      { name: "raw.js", data: js, store: true },
      { name: "icon.png", data: Buffer.alloc(1000, 7) },
    ]);
    withArchive(zip, ".zip", (p) => {
      const x = extractArchive(p);
      try {
        expect(readFileSync(join(x.dir, "bg.js"), "utf8")).toBe(js);
        expect(readFileSync(join(x.dir, "raw.js"), "utf8")).toBe(js);
        expect(readFileSync(join(x.dir, "icon.png")).length).toBe(0);
      } finally {
        x.cleanup();
      }
      expect(existsSync(x.dir)).toBe(false);
    });
  });

  it("tolerates a zip comment", () => {
    const zip = buildZip(fixtureEntries("pass-basic-mv3"), { comment: "built by CI" });
    withArchive(zip, ".zip", (p) => expect(analyzeInput(p, { version: "t" }).browsers.chrome.verdict).toBe("pass"));
  });

  it("reads CRX3 and CRX2 (header, then zip)", () => {
    for (const crx of [3, 2] as const) {
      const buf = buildZip(fixtureEntries("remote-script"), { crx });
      withArchive(buf, ".crx", (p) => {
        expect(listArchive(p).kind).toBe("crx");
        const r = analyzeInput(p, { version: "t" }).browsers.chrome;
        expect(ruleIds(r)).toContain("MV3001");
        expect(r.verdict).toBe("high_rejection_risk");
      });
    }
  });

  it("refuses a bad CRX version and a non-zip file", () => {
    const bad = Buffer.concat([Buffer.from("Cr24"), Buffer.from([9, 0, 0, 0, 0, 0, 0, 0])]);
    withArchive(bad, ".crx", (p) => expect(() => listArchive(p)).toThrow(/CRX version 9/));
    withArchive(Buffer.from("this is not a zip file at all, just text"), ".zip", (p) =>
      expect(() => listArchive(p)).toThrow(ManifestError));
  });

  it("refuses unsupported compression methods and encrypted entries with a clear error", () => {
    const zip = buildZip([{ name: "manifest.json", data: MANIFEST }, { name: "bg.js", data: "x()" }]);
    const cen = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    const second = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]), cen + 4);
    const methodPatched = Buffer.from(zip);
    methodPatched.writeUInt16LE(12, second + 10); // bzip2
    withArchive(methodPatched, ".zip", (p) => expect(() => analyzeInput(p, { version: "t" })).toThrow(/compression method 12/));
    const encPatched = Buffer.from(zip);
    encPatched.writeUInt16LE(0x801, second + 8);
    withArchive(encPatched, ".zip", (p) => expect(() => listArchive(p)).toThrow(/Encrypted/));
  });

  it("zip-bomb guard: an entry that inflates past its declared size is refused", () => {
    const zip = buildZip([{ name: "manifest.json", data: MANIFEST }, { name: "bg.js", data: "a".repeat(100000) }]);
    const cen = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    const second = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]), cen + 4);
    const lied = Buffer.from(zip);
    lied.writeUInt32LE(10, second + 24); // claims 10 bytes uncompressed
    withArchive(lied, ".zip", (p) => expect(() => analyzeInput(p, { version: "t" })).toThrow(/inflate/i));
  });

  it("never writes outside the temp dir (zip-slip) and never creates symlinks", () => {
    const outside = mkdtempSync(join(tmpdir(), "tsl-slip-"));
    try {
      const zip = buildZip([
        { name: "manifest.json", data: MANIFEST },
        { name: "bg.js", data: "console.log(1)" },
        { name: "../../../../../../../../" + outside.slice(1) + "/pwned.js", data: "x" },
        { name: "/" + outside.slice(1) + "/abs.js", data: "x" },
        { name: "link.js", data: "/etc/passwd", mode: 0o120777 },
      ]);
      withArchive(zip, ".zip", (p) => {
        const x = extractArchive(p);
        try {
          expect(x.listing.unsafePaths).toHaveLength(2);
          expect(readdirSync(outside)).toEqual([]);
          expect(readFileSync(join(x.dir, "link.js")).length).toBe(0); // placeholder, not the link target
        } finally {
          x.cleanup();
        }
        const r = analyzeInput(p, { version: "t" }).browsers.chrome;
        expect(r.findings.some((f) => f.ruleId === "PKG001" && /unsafe paths/.test(f.title))).toBe(true);
      });
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("removes its temp dir after success and after errors", () => {
    // Private TMPDIR so parallel test files creating their own temp dirs can't interfere.
    const privateTmp = mkdtempSync(join(tmpdir(), "tsl-tmpdir-"));
    const saved = process.env.TMPDIR;
    process.env.TMPDIR = privateTmp;
    try {
      const zipOk = buildZip(fixtureEntries("pass-basic-mv3"));
      const zipBad = buildZip([{ name: "x/manifest.json", data: MANIFEST }]);
      const okPath = join(privateTmp, "ok.zip");
      const badPath = join(privateTmp, "bad.zip");
      writeFileSync(okPath, zipOk);
      writeFileSync(badPath, zipBad);
      expect(analyzeInput(okPath, { version: "t" }).browsers.chrome.verdict).toBe("pass");
      expect(() => analyzeInput(badPath, { version: "t" })).toThrow();
      expect(readdirSync(privateTmp).filter((n) => n.startsWith("tabsmith-pkg-"))).toEqual([]);
      expect(tmpdir()).toBe(privateTmp); // the archive code really used this TMPDIR
    } finally {
      if (saved === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = saved;
      rmSync(privateTmp, { recursive: true, force: true });
    }
  });
});

describe("archive input: lints what ships", () => {
  for (const name of ["pass-basic-mv3", "remote-script", "eval", "missing-file", "case-mismatch", "dnr-strip-headers", "obfuscated-vendor", "latent-loader", "unused-storage"]) {
    it(`${name}: zip and crx give the same verdict and non-PKG findings as the directory`, () => {
      const dirReport = analyze(fixtureDir(name), { version: "t" }).browsers.chrome;
      for (const [ext, crx] of [[".zip", undefined], [".crx", 3]] as const) {
        withArchive(buildZip(fixtureEntries(name), { crx }), ext, (p) => {
          const r = analyzeInput(p, { version: "t" }).browsers.chrome;
          expect(r.verdict).toBe(dirReport.verdict);
          expect(nonPkg(ruleIds(r))).toEqual(nonPkg(ruleIds(dirReport)));
        });
      }
    });
  }

  it("manifest.json inside a top-level folder → exit-3 error that explains the zip-root rule", () => {
    const zip = buildZip(fixtureEntries("pass-basic-mv3").map((e) => ({ ...e, name: `my-ext/${e.name}` })));
    withArchive(zip, ".zip", (p) => {
      const r = run([p]);
      expect(r.exitCode).toBe(3);
      expect(r.stderr).toMatch(/my-ext\/manifest\.json/);
      expect(r.stderr).toMatch(/ROOT of the zip/);
    });
  });

  it("no manifest anywhere → exit 3; missing archive → exit 3", () => {
    withArchive(buildZip([{ name: "a.js", data: "1" }]), ".zip", (p) => expect(run([p]).exitCode).toBe(3));
    const r = run([join(tmpdir(), "definitely-missing-tsl.zip")]);
    expect(r.exitCode).toBe(3);
    expect(r.stderr).toMatch(/Archive not found/);
  });

  it("build/ and dist/ code inside an archive is scanned (it ships); directory input still skips them", () => {
    const entries: ZipEntryInput[] = [
      { name: "manifest.json", data: MANIFEST },
      { name: "bg.js", data: "console.log(1)" },
      { name: "build/chunk.js", data: 'const s = document.createElement("script"); s.src = "https://cdn.example.com/x.js"; document.head.appendChild(s);' },
    ];
    withArchive(buildZip(entries), ".zip", (p) => {
      expect(ruleIds(analyzeInput(p, { version: "t" }).browsers.chrome)).toContain("MV3001");
    });
    const dir = mkdtempSync(join(tmpdir(), "tsl-dir-"));
    try {
      for (const e of entries) {
        mkdirSync(join(dir, e.name, ".."), { recursive: true });
        writeFileSync(join(dir, e.name), typeof e.data === "string" ? e.data : JSON.stringify(e.data));
      }
      expect(ruleIds(analyze(dir, { version: "t" }).browsers.chrome)).not.toContain("MV3001");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a referenced binary file present in the zip satisfies FUNC001; a missing one is reported", () => {
    const m = { ...MANIFEST, icons: { "128": "icons/128.png", "48": "icons/48.png" } };
    const zip = buildZip([
      { name: "manifest.json", data: m },
      { name: "bg.js", data: "1" },
      { name: "icons/128.png", data: Buffer.alloc(64, 1) },
    ]);
    withArchive(zip, ".zip", (p) => {
      const f = analyzeInput(p, { version: "t" }).browsers.chrome.findings.filter((x) => x.ruleId === "FUNC001");
      expect(f).toHaveLength(1);
      expect(f[0].title).toMatch(/icons\/48\.png/);
    });
  });

  it("CLI: reports the archive path (never the temp dir) and counts package files", () => {
    withArchive(buildZip(fixtureEntries("pass-basic-mv3")), ".zip", (p) => {
      const human = run([p]);
      expect(human.exitCode).toBe(0);
      expect(human.stdout).toContain(p);
      expect(human.stdout).toMatch(/4 files in package/);
      expect(human.stdout).not.toMatch(/tabsmith-pkg-/);
      const json = run([p, "--format", "json"]);
      const parsed = JSON.parse(json.stdout!);
      expect(parsed.inputPath).toBe(p);
      expect(parsed.browsers.chrome.stats.packageFiles).toBe(4);
      expect(json.stdout).not.toMatch(/tabsmith-pkg-/);
    });
  });

  it("a DIRECTORY whose name ends in .zip is still linted as a directory", () => {
    const parent = mkdtempSync(join(tmpdir(), "tsl-dirzip-"));
    try {
      const d = join(parent, "looks-like.zip");
      mkdirSync(d);
      for (const e of fixtureEntries("pass-basic-mv3")) writeFileSync(join(d, e.name), e.data as Buffer);
      const r = run([d, "--format", "json"]);
      expect(r.exitCode).toBe(0);
      expect(JSON.parse(r.stdout!).browsers.chrome.stats.packageFiles).toBeUndefined();
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});
