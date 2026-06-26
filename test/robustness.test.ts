import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeExt } from "./tmp-ext.js";
import { run } from "../src/cli.js";
import { analyze } from "../src/engine/analyze.js";
import { ruleIds } from "./helpers.js";

// Hardening against malformed-but-valid-JSON manifests and hostile references
// (surfaced by the adversarial + correctness review).

describe("manifest robustness (review fixes)", () => {
  it("non-array permissions/host_permissions/content_scripts do not crash — extension is still analyzed", () => {
    const r = analyzeExt({
      "manifest.json": {
        manifest_version: 3,
        name: "t",
        version: "1.0.0",
        permissions: { storage: true }, // object, not array
        optional_permissions: 5, // number
        host_permissions: "<all_urls>", // string
        content_scripts: "nope", // string
        background: { service_worker: "bg.js" },
      },
      "bg.js": "console.log('ok');",
    });
    // Must produce a real report, not an exit-3 crash.
    expect(["pass", "needs_fixes", "high_rejection_risk"]).toContain(r.verdict);
  });

  it("a namespace named like an Object.prototype key (chrome.constructor) does not crash", () => {
    // Bundled/minified code can access chrome.constructor / chrome.toString etc.
    // Lookup maps must be prototype-safe.
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", permissions: ["storage"], background: { service_worker: "bg.js" } },
      "bg.js": "chrome.constructor; chrome.toString(); chrome.hasOwnProperty('x'); chrome.storage.local.get('k');",
    });
    expect(["pass", "needs_fixes", "high_rejection_risk"]).toContain(r.verdict); // no throw
    expect(ruleIds(r)).not.toContain("PERM002"); // storage is declared+used
  });

  it("BOM-prefixed manifest.json still parses", () => {
    const dir = mkdtempSync(join(tmpdir(), "tsl-bom-"));
    const manifest = JSON.stringify({ manifest_version: 3, name: "t", version: "1.0.0" });
    writeFileSync(join(dir, "manifest.json"), "﻿" + manifest);
    const result = run([dir]);
    expect(result.exitCode).toBe(0); // parsed → pass, not exit 3
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("path traversal containment (review fix)", () => {
  it("a '../' manifest reference is NOT read/analyzed and is flagged FUNC001", () => {
    // Put a secret outside the extension dir; reference it from the manifest.
    const parent = mkdtempSync(join(tmpdir(), "tsl-trav-"));
    writeFileSync(join(parent, "secret.js"), "chrome.cookies.get({});"); // would emit PERM002 if analyzed
    const ext = join(parent, "ext");
    mkdirSync(ext);
    writeFileSync(
      join(ext, "manifest.json"),
      JSON.stringify({ manifest_version: 3, name: "t", version: "1.0.0", background: { service_worker: "../secret.js" } })
    );
    const report = analyze(ext, { version: "0.1.0-test" }).browsers.chrome;
    // secret.js was NOT analyzed → no PERM002 from its cookies call
    expect(ruleIds(report)).not.toContain("PERM002");
    // the escaping reference is flagged
    expect(ruleIds(report)).toContain("FUNC001");
    rmSync(parent, { recursive: true, force: true });
  });
});

// Regressions found by running v0.1 against real Google MV3 sample extensions.
describe("real-world false positives (caught on Google sample extensions)", () => {
  it("root-relative '/images/icon.png' is found inside the package (no FUNC001)", () => {
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", action: { default_icon: "/icon.png" } },
      "icon.png": "fake-png-bytes",
    });
    expect(ruleIds(r)).not.toContain("FUNC001");
    expect(r.verdict).toBe("pass");
  });

  it("declarativeNetRequestWithHostAccess satisfies chrome.declarativeNetRequest usage (no PERM002)", () => {
    const r = analyzeExt({
      "manifest.json": {
        manifest_version: 3,
        name: "t",
        version: "1.0.0",
        permissions: ["declarativeNetRequestWithHostAccess"],
        background: { service_worker: "bg.js" },
      },
      "bg.js": "chrome.declarativeNetRequest.updateDynamicRules({ addRules: [], removeRuleIds: [] });",
    });
    expect(ruleIds(r)).not.toContain("PERM002");
  });

  it("declarativeNetRequest used declaratively (manifest rulesets, no JS) is NOT flagged unused", () => {
    const r = analyzeExt({
      "manifest.json": {
        manifest_version: 3,
        name: "t",
        version: "1.0.0",
        permissions: ["declarativeNetRequest"],
        declarative_net_request: { rule_resources: [{ id: "r1", enabled: true, path: "rules.json" }] },
      },
      "rules.json": "[]",
    });
    expect(ruleIds(r)).not.toContain("PERM001");
  });

  it("reading changeInfo.url in chrome.tabs.onUpdated counts as using `tabs` (no PERM001)", () => {
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", permissions: ["tabs"], background: { service_worker: "bg.js" } },
      "bg.js": "chrome.tabs.onUpdated.addListener((tabId, changes) => { if (typeof changes.url === 'string') console.log(changes.url); });",
    });
    expect(ruleIds(r)).not.toContain("PERM001"); // changeInfo.url requires the tabs permission
  });

  it("tab.url read mid-chain (tab.url.startsWith) counts as using `tabs` (no PERM001)", () => {
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", permissions: ["tabs"], background: { service_worker: "bg.js" } },
      "bg.js": "chrome.action.onClicked.addListener((tab) => { if (tab.url.startsWith('http')) console.log(1); });",
    });
    expect(ruleIds(r)).not.toContain("PERM001"); // tabs IS used via the sensitive url read
  });
});

describe("isTabish no longer over-matches (review fix)", () => {
  it("reading table.url does NOT mark `tabs` as used (PERM001 still fires)", () => {
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", permissions: ["tabs"], background: { service_worker: "bg.js" } },
      "bg.js": "const table = { url: 'x' }; console.log(table.url);",
    });
    expect(ruleIds(r)).toContain("PERM001"); // tabs unused — not masked by table.url
  });
});

describe("--help and --min-severity semantics (review fixes)", () => {
  it("--help exits 0 with usage on stdout", () => {
    const r = run(["--help"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/Usage/);
  });

  it("--min-severity reject gates the verdict too: a fix-only extension exits 0 (eslint --quiet semantics)", () => {
    const dir = mkdtempSync(join(tmpdir(), "tsl-ms-"));
    writeFileSync(
      join(dir, "manifest.json"),
      JSON.stringify({ manifest_version: 3, name: "t", version: "1.0.0", permissions: ["storage"], background: { service_worker: "bg.js" } })
    );
    writeFileSync(join(dir, "bg.js"), "console.log('storage unused -> PERM001 fix');");
    expect(run([dir]).exitCode).toBe(1); // default: needs_fixes
    expect(run([dir, "--min-severity", "reject"]).exitCode).toBe(0); // gated away
    rmSync(dir, { recursive: true, force: true });
  });
});
