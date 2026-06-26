import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { ruleIds } from "./helpers.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });

describe("U7: permission rules", () => {
  it("activeTab with no gesture entry point → PERM001 fix-level warning", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ permissions: ["activeTab"], background: { service_worker: "bg.js" } }),
      "bg.js": "console.log('no gesture');",
    });
    const p = r.findings.find((f) => f.ruleId === "PERM001" && f.title.includes("activeTab"));
    expect(p?.severity).toBe("fix");
  });

  it("chrome.cookies.get without cookies → PERM002 (reject)", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "chrome.cookies.get({ url: 'https://x.com', name: 'a' });",
    });
    const p = r.findings.find((f) => f.ruleId === "PERM002");
    expect(p?.severity).toBe("reject");
    expect(r.verdict).toBe("high_rejection_risk");
  });

  it("chrome.tabs.create without tabs → NO PERM002", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "chrome.tabs.create({ url: 'https://x.com' });",
    });
    expect(ruleIds(r)).not.toContain("PERM002");
  });

  it("dynamic access lowers confidence: no high-confidence unused finding", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ permissions: ["storage"], background: { service_worker: "bg.js" } }),
      "bg.js": "const name = 'storage'; chrome[name].local.get('k');",
    });
    const p = r.findings.find((f) => f.ruleId === "PERM001");
    expect(p).toBeTruthy();
    expect(p!.confidence).not.toBe("high"); // dynamic access detected → degraded
  });
});
