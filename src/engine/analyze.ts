import type {
  ExtensionModel,
  LintReport,
  Finding,
  HostAccessSignal,
  Severity,
} from "./model.js";
import { loadManifest } from "./manifest.js";
import { discoverFiles, isScript, isHtml } from "./file-discovery.js";
import { collectManifestRefs } from "./manifest-refs.js";
import { parseScript } from "../parse/parse-script.js";
import { extractFromScripts } from "../parse/extract-api-calls.js";
import { runRules } from "../rules/index.js";
import { computeVerdict, filterByMinSeverity } from "./verdict.js";

export interface AnalyzeOptions {
  version: string;
  minSeverity?: Severity;
}

/** Pure-ish engine entry point: directory in → LintReport out. Only manifest
 *  loading and file discovery touch the filesystem. Throws ManifestError (→ CLI
 *  exit 3) when the manifest is missing or invalid. */
export function analyze(rootDir: string, options: AnalyzeOptions): LintReport {
  const { manifest, raw } = loadManifest(rootDir);

  const manifestRefs = collectManifestRefs(manifest);
  const files = discoverFiles(rootDir, manifestRefs);
  const htmlFiles = files.filter((f) => isHtml(f.relPath));
  const scriptFiles = files.filter((f) => isScript(f.relPath)).map(parseScript);

  const extraction = extractFromScripts(scriptFiles);
  const hostAccessSignals: HostAccessSignal[] = [
    ...extraction.hostAccessSignals,
    ...deriveHostSignals(extraction.apiCalls),
    ...((manifest as any).content_scripts?.length ? [{ kind: "contentScript", file: "manifest.json" } as HostAccessSignal] : []),
  ];

  const model: ExtensionModel = {
    rootDir,
    manifest,
    manifestRaw: raw,
    files,
    scriptFiles,
    htmlFiles,
    apiCalls: extraction.apiCalls,
    sensitiveTabReads: extraction.sensitiveTabReads,
    dynamicApiAccess: extraction.dynamicApiAccess,
    hostAccessSignals,
    manifestRefs: manifestRefs.all,
  };

  const ruleFindings = runRules(model);
  const parseFindings: Finding[] = scriptFiles
    .filter((s) => s.parseError)
    .map((s) => ({
      ruleId: "PARSE",
      severity: "info" as Severity,
      confidence: "low" as const,
      title: "File could not be parsed",
      message: `${s.relPath} failed to parse; its API usage was not analyzed. Findings for code in this file may be incomplete.`,
      file: s.relPath,
    }));

  const allFindings = [...ruleFindings, ...parseFindings];
  // --min-severity is a threshold, not just a display filter: it gates both the
  // reported findings AND the verdict/exit code. This mirrors eslint --quiet
  // (suppressing warnings makes a warning-only run exit 0). So `--min-severity
  // reject` on a fix-only extension yields `pass`/exit 0 by design — the caller
  // opted out of caring about fix-level findings.
  const findings = filterByMinSeverity(allFindings, options.minSeverity ?? "info");
  const verdict = computeVerdict(findings);

  const scriptsParsed = scriptFiles.filter((s) => !s.parseError).length;

  return {
    tool: "tabsmith-lint",
    version: options.version,
    inputPath: rootDir,
    manifestVersion: manifest.manifest_version,
    browsers: {
      chrome: {
        verdict,
        findings,
        stats: {
          filesScanned: files.length,
          scriptsParsed,
          parseErrors: scriptFiles.length - scriptsParsed,
        },
      },
    },
  };
}

function deriveHostSignals(apiCalls: ExtensionModel["apiCalls"]): HostAccessSignal[] {
  const out: HostAccessSignal[] = [];
  for (const c of apiCalls) {
    if (c.namespace === "cookies") out.push({ kind: "cookies", file: c.file, line: c.line });
    else if (c.namespace === "webRequest") out.push({ kind: "webRequest", file: c.file, line: c.line });
    else if (c.namespace === "declarativeNetRequest") out.push({ kind: "declarativeNetRequest", file: c.file, line: c.line });
    else if (c.namespace === "scripting" && c.path.includes("executeScript")) out.push({ kind: "scripting.executeScript", file: c.file, line: c.line });
  }
  return out;
}
