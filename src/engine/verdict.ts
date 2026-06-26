import type { Finding, Severity, Verdict } from "./model.js";

/** Canonical severity ranking — the single source of truth for ordering and
 *  filtering. Higher = more severe. */
export const SEVERITY_RANK: Record<Severity, number> = { reject: 2, fix: 1, info: 0 };
/** Most-severe-first order, for grouped display and stable sorting. */
export const SEVERITY_ORDER: Severity[] = ["reject", "fix", "info"];

export function filterByMinSeverity(findings: Finding[], min: Severity): Finding[] {
  return findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[min]);
}

export function computeVerdict(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "reject")) return "high_rejection_risk";
  if (findings.some((f) => f.severity === "fix")) return "needs_fixes";
  return "pass";
}

export function verdictExitCode(verdict: Verdict): 0 | 1 | 2 {
  switch (verdict) {
    case "pass":
      return 0;
    case "needs_fixes":
      return 1;
    case "high_rejection_risk":
      return 2;
  }
}
