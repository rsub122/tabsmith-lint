import { describe, it, expect } from "vitest";
import { computeVerdict, verdictExitCode, filterByMinSeverity } from "../src/engine/verdict.js";
import type { Finding } from "../src/engine/model.js";

const f = (severity: Finding["severity"]): Finding => ({
  ruleId: "X",
  severity,
  confidence: "high",
  title: "t",
  message: "m",
});

describe("U6: verdict computation", () => {
  it("empty findings → pass → exit 0", () => {
    expect(computeVerdict([])).toBe("pass");
    expect(verdictExitCode("pass")).toBe(0);
  });

  it("fix but no reject → needs_fixes → exit 1", () => {
    expect(computeVerdict([f("fix"), f("info")])).toBe("needs_fixes");
    expect(verdictExitCode("needs_fixes")).toBe(1);
  });

  it("any reject → high_rejection_risk → exit 2", () => {
    expect(computeVerdict([f("fix"), f("reject")])).toBe("high_rejection_risk");
    expect(verdictExitCode("high_rejection_risk")).toBe(2);
  });

  it("--min-severity reject hides fix/info", () => {
    const kept = filterByMinSeverity([f("reject"), f("fix"), f("info")], "reject");
    expect(kept.map((x) => x.severity)).toEqual(["reject"]);
  });
});
