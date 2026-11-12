import type { ExtensionModel, Finding, Severity } from "../engine/model.js";
import { walk } from "../parse/parse-script.js";
import { findLine, findLineByIndex } from "../engine/source-lines.js";

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
      // importScripts("https://...") — the classic service-worker remote loader.
      // Only string-literal (or expression-free template) arguments are judged;
      // computed URLs are left alone (no guessing).
      if (node.type === "CallExpression" && isImportScriptsCallee(node.callee)) {
        for (const arg of node.arguments ?? []) {
          const url = staticString(arg);
          if (isRemote(url)) findings.push(remoteImport(script.relPath, node, url, "importScripts"));
        }
      }
    });
  }
  return findings;
}

function isRemote(v: unknown): v is string {
  return typeof v === "string" && /^(https?:)?\/\//i.test(v);
}

/** importScripts, self.importScripts, globalThis.importScripts. */
function isImportScriptsCallee(callee: any): boolean {
  if (callee?.type === "Identifier") return callee.name === "importScripts";
  return (
    callee?.type === "MemberExpression" &&
    !callee.computed &&
    callee.property?.type === "Identifier" &&
    callee.property.name === "importScripts" &&
    callee.object?.type === "Identifier" &&
    (callee.object.name === "self" || callee.object.name === "globalThis")
  );
}

/** The value of a string literal or an expression-free template literal, else null. */
function staticString(arg: any): string | null {
  if (arg?.type === "StringLiteral") return arg.value;
  if (arg?.type === "TemplateLiteral" && arg.expressions?.length === 0 && arg.quasis?.length === 1) {
    return arg.quasis[0].value?.cooked ?? null;
  }
  return null;
}

function remoteImport(file: string, node: any, url: string, via: "import" | "importScripts" = "import"): Finding {
  return {
    ruleId: "MV3001",
    severity: "reject",
    confidence: "high",
    title: "Remotely hosted code referenced",
    message:
      via === "importScripts"
        ? `importScripts("${url}") loads code from a remote URL, which Manifest V3 forbids.`
        : `import of "${url}" loads code from a remote URL, which Manifest V3 forbids.`,
    file,
    line: node.loc?.start.line,
    chromeViolationId: "Blue Argon",
    fixHint:
      via === "importScripts"
        ? "Bundle the script inside the extension package and importScripts() the local copy."
        : "Bundle the dependency inside the extension package instead of importing it remotely.",
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

// MV3004 — extension-page CSP that Chrome's Manifest V3 forbids. For
// `content_security_policy.extension_pages`, script-src / object-src / worker-src
// may only contain 'self', 'none', 'wasm-unsafe-eval', 'inline-speculation-rules'
// and localhost sources; anything laxer (unsafe-eval, unsafe-inline, remote
// origins) makes Chrome refuse to load the extension. The `sandbox` policy is
// exempt and is never inspected. Nonces/hashes are not judged (conservative).
const CSP_RESTRICTED = new Set(["script-src", "object-src", "worker-src"]);
const CSP_ALLOWED_KEYWORDS = new Set(["'self'", "'none'", "'wasm-unsafe-eval'", "'inline-speculation-rules'"]);
const CSP_LOCALHOST_RE = /^(https?:\/\/)?(localhost|127\.0\.0\.1)(:(\d+|\*))?(\/.*)?$/i;

function cspViolations(policy: string): string[] {
  const bad: string[] = [];
  for (const directive of policy.split(";")) {
    const [rawName, ...sources] = directive.trim().split(/\s+/);
    const name = rawName?.toLowerCase();
    if (!name || !CSP_RESTRICTED.has(name)) continue;
    for (const src of sources) {
      const lower = src.toLowerCase();
      if (CSP_ALLOWED_KEYWORDS.has(lower)) continue;
      if (lower.startsWith("'nonce-") || lower.startsWith("'sha")) continue; // not judged
      if (lower === "'unsafe-eval'" || lower === "'unsafe-inline'") {
        bad.push(`${name} ${src}`);
      } else if (lower.startsWith("'")) {
        continue; // unknown keyword — don't guess
      } else if (!CSP_LOCALHOST_RE.test(src)) {
        bad.push(`${name} ${src}`); // remote origin, wildcard, or scheme source
      }
    }
  }
  return bad;
}

function mv3004(model: ExtensionModel): Finding[] {
  if (model.manifest.manifest_version !== 3) return [];
  const csp = (model.manifest as any).content_security_policy;
  if (csp === undefined || csp === null) return [];
  const line = findLine(model.manifestRaw, "content_security_policy");

  if (typeof csp === "string") {
    return [{
      ruleId: "MV3004",
      severity: "reject",
      confidence: "high",
      title: "content_security_policy must be an object in Manifest V3",
      message: 'content_security_policy is a string (the Manifest V2 form). Manifest V3 requires an object such as {"extension_pages": "script-src \'self\'; object-src \'self\'"}.',
      file: "manifest.json",
      line,
      fixHint: 'Use {"extension_pages": "..."} (and "sandbox" if needed) instead of a single string.',
    }];
  }

  const pages = csp && typeof csp === "object" ? (csp as any).extension_pages : undefined;
  if (typeof pages !== "string") return [];
  const bad = cspViolations(pages);
  if (bad.length === 0) return [];
  return [{
    ruleId: "MV3004",
    severity: "reject",
    confidence: "high",
    title: "extension_pages CSP is looser than Manifest V3 allows",
    message: `content_security_policy.extension_pages contains ${bad.map((b) => `"${b}"`).join(", ")}. Manifest V3 only allows 'self', 'none', 'wasm-unsafe-eval' and localhost sources for script-src, object-src and worker-src, so Chrome will not load or accept this extension.`,
    file: "manifest.json",
    line: findLine(model.manifestRaw, "extension_pages") ?? line,
    chromeViolationId: "Blue Argon",
    fixHint: "Remove the remote origins and 'unsafe-*' keywords; bundle code locally. If eval is unavoidable, move that code to a sandboxed page (content_security_policy.sandbox).",
  }];
}

export const mv3Rules = [mv3001, mv3002, mv3003, mv3004];
