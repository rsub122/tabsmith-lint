import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { ruleIds } from "./helpers.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });

describe("U9: file rules", () => {
  it("missing service worker → FUNC001 (reject)", () => {
    const r = analyzeExt({ "manifest.json": mv3({ background: { service_worker: "background.js" } }) });
    expect(ruleIds(r)).toContain("FUNC001");
    expect(r.verdict).toBe("high_rejection_risk");
  });

  it("missing icon file → FUNC001", () => {
    const r = analyzeExt({ "manifest.json": mv3({ icons: { "16": "icon16.png" } }) });
    const f = r.findings.find((x) => x.ruleId === "FUNC001");
    expect(f?.message).toMatch(/icon16\.png/);
  });

  it("case-only mismatch → FUNC002 (fix)", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ action: { default_popup: "Popup.html" } }),
      "popup.html": "<html></html>",
    });
    expect(ruleIds(r)).toContain("FUNC002");
    expect(r.findings.find((f) => f.ruleId === "FUNC002")!.severity).toBe("fix");
  });
});
