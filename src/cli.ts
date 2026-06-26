#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Severity } from "./engine/model.js";
import { analyze } from "./engine/analyze.js";
import { ManifestError } from "./engine/manifest.js";
import { verdictExitCode } from "./engine/verdict.js";
import { renderHuman } from "./reporters/human.js";
import { renderJson } from "./reporters/json.js";

export interface CliResult {
  exitCode: 0 | 1 | 2 | 3;
  stdout?: string;
  stderr?: string;
}

const USAGE =
  "Usage: tabsmith-lint <extension-dir> [--format human|json] [--browser chrome] [--min-severity reject|fix|info]";

function version(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    return JSON.parse(readFileSync(join(here, "../package.json"), "utf8")).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function helpText(): string {
  return `tabsmith-lint v${version()} - pre-submission compliance linter for Manifest V3 Chrome extensions

Point it at an unpacked extension directory and it flags likely Chrome Web Store
rejection risks before you submit:
  - unused / excessive permissions (the "Purple Potassium" rejection)
  - Manifest V3 violations: remotely hosted code, string execution, Manifest V2
  - broken packaging: missing or wrong-case file references

${USAGE}

Options:
  --format human|json              output format (default: human)
  --browser chrome                 target browser (only chrome in v0.1)
  --min-severity reject|fix|info   minimum severity to report (default: info)
  -v, --version                    print version
  -h, --help                       show this help

Exit codes: 0 pass | 1 needs fixes | 2 high rejection risk | 3 tool error
Docs: https://github.com/rsub122/tabsmith-lint`;
}

export function run(argv: string[]): CliResult {
  let dir: string | undefined;
  let format = "human";
  let browser = "chrome";
  let minSeverity: Severity = "info";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--format") format = argv[++i];
    else if (arg === "--browser") browser = argv[++i];
    else if (arg === "--min-severity") minSeverity = argv[++i] as Severity;
    else if (arg === "-h" || arg === "--help") return { exitCode: 0, stdout: helpText() };
    else if (arg === "-v" || arg === "--version") return { exitCode: 0, stdout: version() };
    else if (arg.startsWith("--")) return { exitCode: 3, stderr: `Unknown option: ${arg}\n${USAGE}` };
    else if (dir === undefined) dir = arg;
    else return { exitCode: 3, stderr: `Unexpected argument: ${arg}\n${USAGE}` };
  }

  if (!dir) return { exitCode: 3, stderr: `No extension directory provided.\n${USAGE}` };
  if (browser !== "chrome") return { exitCode: 3, stderr: `Only --browser chrome is supported in v0.1 (got "${browser}").` };
  if (!["human", "json"].includes(format)) return { exitCode: 3, stderr: `Invalid --format "${format}" (expected human|json).` };
  if (!["reject", "fix", "info"].includes(minSeverity)) return { exitCode: 3, stderr: `Invalid --min-severity "${minSeverity}" (expected reject|fix|info).` };

  let report;
  try {
    report = analyze(dir, { version: version(), minSeverity });
  } catch (e) {
    const msg = e instanceof ManifestError ? e.message : (e as Error).message;
    return { exitCode: 3, stderr: `error: ${msg}` };
  }

  const stdout = format === "json" ? renderJson(report) : renderHuman(report, minSeverity);
  return { exitCode: verdictExitCode(report.browsers.chrome.verdict), stdout };
}

// Run as a CLI only when invoked directly (not when imported by tests). npm/npx
// install the bin as a SYMLINK (node_modules/.bin/tabsmith-lint -> dist/cli.js),
// so process.argv[1] is the symlink path while import.meta.url is the real file —
// compare realpaths, or the published binary silently does nothing.
let invokedDirectly = false;
try {
  invokedDirectly = !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch {
  invokedDirectly = false;
}
if (invokedDirectly) {
  const result = run(process.argv.slice(2));
  if (result.stdout) console.log(result.stdout);
  if (result.stderr) console.error(result.stderr);
  process.exit(result.exitCode);
}
