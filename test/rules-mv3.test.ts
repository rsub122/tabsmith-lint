import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { ruleIds } from "./helpers.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });

describe("U8: MV3 rules", () => {
  it("import('https://...') → MV3001", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "import('https://example.com/app.js');",
    });
    expect(ruleIds(r)).toContain("MV3001");
  });

  it("new Function(...) → MV3002", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "const f = new Function('return 1');",
    });
    expect(ruleIds(r)).toContain("MV3002");
  });

  it('setTimeout("run()", 100) → MV3002 but setTimeout(() => run(), 100) → no MV3002', () => {
    const bad = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "setTimeout('run()', 100);",
    });
    expect(ruleIds(bad)).toContain("MV3002");

    const good = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "setTimeout(() => run(), 100);",
    });
    expect(ruleIds(good)).not.toContain("MV3002");
  });

  it("manifest_version 2 → MV3003 + exit-equivalent high_rejection_risk", () => {
    const r = analyzeExt({ "manifest.json": { manifest_version: 2, name: "t", version: "1.0.0" } });
    expect(ruleIds(r)).toContain("MV3003");
    expect(r.verdict).toBe("high_rejection_risk");
  });
});
