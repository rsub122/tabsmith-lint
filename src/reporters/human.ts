import type { LintReport, Finding, Severity, Verdict } from "../engine/model.js";
import { SEVERITY_ORDER } from "../engine/verdict.js";

// Optional interest-signal line, shown once after a human-mode run (suppressed in
// JSON and under --min-severity reject). Off by default in v0.1 — enable only when
// WAITLIST_URL points to a real page. Behind a constant so it's easy to toggle.
export const SHOW_DEMAND_LINE = false;
export const WAITLIST_URL = "https://tabsmith-lint.dev/monitor-waitlist";

const VERDICT_HEADER: Record<Verdict, string> = {
  pass: "PASS",
  needs_fixes: "NEEDS FIXES",
  high_rejection_risk: "HIGH REJECTION RISK",
};

const VERDICT_WORDS: Record<Verdict, string> = {
  pass: "pass",
  needs_fixes: "needs fixes",
  high_rejection_risk: "high rejection risk",
};

export function renderHuman(report: LintReport, minSeverity: Severity = "info"): string {
  const chrome = report.browsers.chrome;
  const lines: string[] = [];

  lines.push(`tabsmith-lint v${report.version} analyzing ${report.inputPath}`);
  const mv = report.manifestVersion !== undefined ? `Manifest V${report.manifestVersion}` : "Manifest version unknown";
  lines.push(`${mv}, ${chrome.stats.filesScanned} files scanned, ${chrome.stats.scriptsParsed} scripts parsed`);
  lines.push("");
  lines.push(`CHROME: ${VERDICT_HEADER[chrome.verdict]}`);
  lines.push("");

  if (chrome.findings.length === 0) {
    lines.push("No findings.");
  } else {
    for (const severity of SEVERITY_ORDER) {
      for (const f of chrome.findings.filter((x) => x.severity === severity)) {
        lines.push(...renderFinding(f));
        lines.push("");
      }
    }
  }

  lines.push(`Verdict: ${VERDICT_WORDS[chrome.verdict]} (${countLabel(chrome.findings)})`);

  if (SHOW_DEMAND_LINE && minSeverity !== "reject") {
    lines.push("");
    lines.push(`Want alerts if your published extension is removed or its review status changes? → ${WAITLIST_URL}`);
  }

  return lines.join("\n");
}

function renderFinding(f: Finding): string[] {
  const out: string[] = [];
  const violation = f.chromeViolationId ? ` (${f.chromeViolationId})` : "";
  out.push(`[${f.severity}] ${f.ruleId} ${f.title}${violation}`);
  if (f.file) {
    let loc = f.file;
    if (f.line !== undefined) loc += `:${f.line}`;
    if (f.column !== undefined) loc += `:${f.column}`;
    out.push(`  ${loc}`);
  }
  out.push(`  ${f.message}`);
  if (f.fixHint) out.push(`  Fix: ${f.fixHint}`);
  return out;
}

function countLabel(findings: Finding[]): string {
  const counts: Record<Severity, number> = { reject: 0, fix: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const parts: string[] = [];
  if (counts.reject) parts.push(`${counts.reject} reject`);
  if (counts.fix) parts.push(`${counts.fix} fix`);
  if (counts.info) parts.push(`${counts.info} info`);
  return parts.length ? parts.join(", ") : "no findings";
}
