import { describe, it, expect } from "vitest";
import { run } from "../src/cli.js";
import { fixtureDir, fixtureReport, ruleIds } from "./helpers.js";

// (fixture, expected rule present, verdict, exit code)
const CASES: Array<[string, string | null, string, number]> = [
  ["pass-basic-mv3", null, "pass", 0],
  ["unused-storage", "PERM001", "needs_fixes", 1],
  ["missing-storage", "PERM002", "high_rejection_risk", 2],
  ["tabs-basic-no-tabs-needed", "PERM001", "needs_fixes", 1],
  ["tabs-sensitive-read", null, "pass", 0],
  ["active-tab-redundant", "PERM003", "needs_fixes", 1],
  ["broad-hosts", "PERM005", "needs_fixes", 1],
  ["remote-script", "MV3001", "high_rejection_risk", 2],
  ["eval", "MV3002", "needs_fixes", 1],
  ["mv2", "MV3003", "high_rejection_risk", 2],
  ["missing-file", "FUNC001", "high_rejection_risk", 2],
  ["case-mismatch", "FUNC002", "needs_fixes", 1],
];

describe("e2e: every fixture produces the expected verdict + finding + exit code", () => {
  for (const [name, ruleId, verdict, exitCode] of CASES) {
    it(`${name} → ${verdict}`, () => {
      const report = fixtureReport(name);
      expect(report.verdict).toBe(verdict);
      if (ruleId) {
        expect(ruleIds(report)).toContain(ruleId);
      } else {
        // pass fixtures: nothing above info
        expect(report.findings.every((f) => f.severity === "info")).toBe(true);
      }

      // human-mode CLI exit code
      const human = run([fixtureDir(name)]);
      expect(human.exitCode).toBe(exitCode);

      // json-mode CLI: parses, lists the expected ruleId, matches verdict
      const jsonRun = run([fixtureDir(name), "--format", "json"]);
      expect(jsonRun.exitCode).toBe(exitCode);
      const parsed = JSON.parse(jsonRun.stdout!);
      expect(parsed.browsers.chrome.verdict).toBe(verdict);
      if (ruleId) {
        expect(parsed.browsers.chrome.findings.map((f: any) => f.ruleId)).toContain(ruleId);
      }
    });
  }
});

describe("KTD 3: PERM001 ships at fix severity, never reject, in v0.1", () => {
  it("a high-confidence unused permission is fix, producing needs_fixes (not high_rejection_risk)", () => {
    const report = fixtureReport("unused-storage");
    const perm001 = report.findings.filter((f) => f.ruleId === "PERM001");
    expect(perm001.length).toBeGreaterThan(0);
    expect(perm001.every((f) => f.severity === "fix")).toBe(true);
    expect(perm001.some((f) => f.confidence === "high")).toBe(true);
    expect(report.verdict).toBe("needs_fixes");
  });
});
