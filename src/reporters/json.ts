import type { LintReport } from "../engine/model.js";

export function renderJson(report: LintReport): string {
  return JSON.stringify(report, null, 2);
}
