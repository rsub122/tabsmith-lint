import { describe, it, expect } from "vitest";
import { analyze } from "../src/engine/analyze.js";
import { renderHuman } from "../src/reporters/human.js";
import { renderJson } from "../src/reporters/json.js";
import { fixtureDir } from "./helpers.js";

function report(name: string, minSeverity?: "reject" | "fix" | "info") {
  return analyze(fixtureDir(name), { version: "0.1.0-test", minSeverity });
}

describe("U10: reporters", () => {
  it("human output groups by severity and includes fix hints", () => {
    const out = renderHuman(report("active-tab-redundant"));
    expect(out).toMatch(/CHROME: NEEDS FIXES/);
    expect(out).toMatch(/\[fix\] PERM003/);
    expect(out).toMatch(/Fix: /);
  });

  it("JSON output matches the LintReport shape including stats", () => {
    const json = JSON.parse(renderJson(report("missing-storage")));
    expect(json.tool).toBe("tabsmith-lint");
    expect(json.browsers.chrome.stats).toHaveProperty("filesScanned");
    expect(json.browsers.chrome.stats).toHaveProperty("scriptsParsed");
    expect(json.browsers.chrome.stats).toHaveProperty("parseErrors");
    expect(json.browsers.chrome.findings[0].ruleId).toBe("PERM002");
  });

  it("--min-severity reject hides fix/info findings", () => {
    const r = report("broad-hosts", "reject"); // only a PERM005 (fix) finding
    expect(r.browsers.chrome.findings.length).toBe(0);
  });

  // The optional interest-signal line is OFF by default in v0.1 (no dead link shipped).
  it("interest-signal line does not appear in human or JSON output", () => {
    expect(renderHuman(report("pass-basic-mv3"))).not.toMatch(/monitor-waitlist|review status changes/);
    expect(renderJson(report("pass-basic-mv3"))).not.toMatch(/monitor-waitlist|review status changes/);
  });
});
