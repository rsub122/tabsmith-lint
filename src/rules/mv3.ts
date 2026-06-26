import type { ExtensionModel, Finding, Severity } from "../engine/model.js";
import { walk } from "../parse/parse-script.js";
import { findLineByIndex } from "../engine/source-lines.js";

// MV3002 (string execution: eval/new Function/string timers) ships at `fix`, not
// `reject`, in v0.1. The pattern is a real MV3 CSP concern, but static analysis
// cannot tell whether the call is reachable or runs in a sandboxed context — and
// it commonly appears in bundled libraries (LESS/CSS compilers, JSON-parse
// fallbacks) of extensions that are published and working. Flagging those as
// "high rejection risk" cries wolf and erodes trust. Surface it to verify, don't
// condemn. Single constant so it can be promoted once context analysis exists.
// (MV3001 remote code and MV3003 manifest_version 2 stay `reject` — deterministic.)
export const MV3002_SEVERITY: Severity = "fix";

const REMOTE_SCRIPT_RE = /<script[^>]*\bsrc\s*=\s*["']((?:https?:)?\/\/[^"']+)["']/gi;

/** MV3001 — remotely hosted code (HTML remote <script src>, remote import/import()). */
function mv3001(model: ExtensionModel): Finding[] {
  const findings: Finding[] = [];

  for (const html of model.htmlFiles) {
    let m: RegExpExecArray | null;
    REMOTE_SCRIPT_RE.lastIndex = 0;
    while ((m = REMOTE_SCRIPT_RE.exec(html.content)) !== null) {
      findings.push({
        ruleId: "MV3001",
        severity: "reject",
        confidence: "high",
        title: "Remotely hosted code referenced",
        message: `<script src="${m[1]}"> loads code from a remote URL, which Manifest V3 forbids.`,
        file: html.relPath,
        line: findLineByIndex(html.content, m.index),
        chromeViolationId: "Blue Argon",
        fixHint: "Bundle the script inside the extension package instead of loading it remotely.",
      });
    }
  }

  for (const script of model.scriptFiles) {
    if (!script.ast) continue;
    walk(script.ast, (node) => {
      // static import of a remote URL
      if (node.type === "ImportDeclaration" && isRemote(node.source?.value)) {
        findings.push(remoteImport(script.relPath, node, node.source.value));
      }
      // dynamic import() of a remote URL
      if (node.type === "CallExpression" && node.callee?.type === "Import" && isRemote(node.arguments?.[0]?.value)) {
        findings.push(remoteImport(script.relPath, node, node.arguments[0].value));
      }
    });
  }
  return findings;
}

function isRemote(v: unknown): v is string {
  return typeof v === "string" && /^(https?:)?\/\//i.test(v);
}

function remoteImport(file: string, node: any, url: string): Finding {
  return {
    ruleId: "MV3001",
    severity: "reject",
    confidence: "high",
    title: "Remotely hosted code referenced",
    message: `import of "${url}" loads code from a remote URL, which Manifest V3 forbids.`,
    file,
    line: node.loc?.start.line,
    chromeViolationId: "Blue Argon",
    fixHint: "Bundle the dependency inside the extension package instead of importing it remotely.",
  };
}

const STRING_TIMERS = new Set(["setTimeout", "setInterval"]);

/** MV3002 — string execution (eval, new Function, string-form timers). */
function mv3002(model: ExtensionModel): Finding[] {
  const findings: Finding[] = [];
  for (const script of model.scriptFiles) {
    if (!script.ast) continue;
    walk(script.ast, (node) => {
      let what: string | null = null;
      if (node.type === "CallExpression" && node.callee?.type === "Identifier" && node.callee.name === "eval") {
        what = "eval()";
      } else if (node.type === "NewExpression" && node.callee?.type === "Identifier" && node.callee.name === "Function") {
        what = "new Function()";
      } else if (
        node.type === "CallExpression" &&
        node.callee?.type === "Identifier" &&
        STRING_TIMERS.has(node.callee.name) &&
        isStringArg(node.arguments?.[0])
      ) {
        what = `${node.callee.name}("...")`;
      }
      if (what) {
        findings.push({
          ruleId: "MV3002",
          severity: MV3002_SEVERITY,
          confidence: "medium",
          title: `String execution via ${what}`,
          message: `${what} executes a string as code. Manifest V3's CSP blocks this in extension contexts unless it runs in a sandboxed page or is unreachable. Verify whether this code path actually runs.`,
          file: script.relPath,
          line: node.loc?.start.line,
          column: node.loc?.start.column,
          chromeViolationId: "Blue Argon",
          fixHint: "Replace string execution with a real function, or confine it to a sandboxed page if it must remain.",
        });
      }
    });
  }
  return findings;
}

function isStringArg(arg: any): boolean {
  return arg?.type === "StringLiteral" || arg?.type === "TemplateLiteral";
}

/** MV3003 — Manifest V2. */
function mv3003(model: ExtensionModel): Finding[] {
  if (model.manifest.manifest_version !== 2) return [];
  return [{
    ruleId: "MV3003",
    severity: "reject",
    confidence: "high",
    title: "Manifest V2 is no longer accepted",
    message: "manifest_version is 2. Chrome Web Store requires Manifest V3.",
    file: "manifest.json",
    fixHint: "Migrate the extension to Manifest V3.",
  }];
}

export const mv3Rules = [mv3001, mv3002, mv3003];
