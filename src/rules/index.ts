import type { ExtensionModel, Finding, Rule } from "../engine/model.js";
import { SEVERITY_RANK } from "../engine/verdict.js";
import { permissionRules } from "./permissions.js";
import { mv3Rules } from "./mv3.js";
import { fileRules } from "./files.js";

export const allRules: Rule[] = [...permissionRules, ...mv3Rules, ...fileRules];

/** Run every rule and return all findings, ordered reject → fix → info. */
export function runRules(model: ExtensionModel): Finding[] {
  const findings = allRules.flatMap((rule) => rule(model));
  return findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}
