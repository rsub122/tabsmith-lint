import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyze } from "../src/engine/analyze.js";
import { parseScript } from "../src/parse/parse-script.js";
import type { ScriptFile, BrowserReport } from "../src/engine/model.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const FIXTURES = join(HERE, "..", "fixtures");

export function fixtureDir(name: string): string {
  return join(FIXTURES, name);
}

export function fixtureReport(name: string): BrowserReport {
  return analyze(fixtureDir(name), { version: "0.1.0-test" }).browsers.chrome;
}

export function ruleIds(report: BrowserReport): string[] {
  return report.findings.map((f) => f.ruleId);
}

/** Parse an inline source string into a ScriptFile for extraction tests. */
export function script(source: string, relPath = "inline.js"): ScriptFile {
  return parseScript({ relPath, absPath: relPath, content: source, discoveredBy: "fallback" });
}
