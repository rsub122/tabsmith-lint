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

/** MV3001 — remotely hosted code (HTML remote <script src>, remote import/import(),
 *  importScripts, remote src on a JS-created <script> element, and remote entries
 *  in chrome.scripting.executeScript({files}) / registerContentScripts({js})). */
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
    findings.push(...injectedRemoteScripts(script.relPath, script.ast));
    findings.push(...remoteScriptingFiles(script.relPath, script.ast));
  }
  return findings;
}

// --- Injected <script> elements -------------------------------------------
// `const s = document.createElement("script"); s.src = "https://…"` (or
// `s.setAttribute("src", "https://…")`, or `Object.assign(s, {src: "https://…"})`)
// injects remotely hosted code exactly like an HTML <script src>. Precision first:
//  - only elements created via `document.createElement("script")` (or
//    `<x>.document` / `<x>.ownerDocument`) count — img/iframe/link/etc. never do;
//  - a variable is tracked only if EVERY binding of that name in the file is such
//    a createElement call (no parameter, other initializer or reassignment with
//    the same name), so reused/minified names are skipped, never guessed;
//  - only literal http(s):// or protocol-relative URLs are judged (computed URLs,
//    local paths and chrome.runtime.getURL(...) are left alone);
//  - fetch/XHR of remote JSON or data is not code execution and is never flagged.

function isScriptCreate(node: any): boolean {
  if (node?.type !== "CallExpression") return false;
  const callee = node.callee;
  if (callee?.type !== "MemberExpression" || callee.computed) return false;
  if (callee.property?.type !== "Identifier" || callee.property.name !== "createElement") return false;
  const obj = callee.object;
  const isDoc =
    (obj?.type === "Identifier" && obj.name === "document") ||
    (obj?.type === "MemberExpression" &&
      !obj.computed &&
      obj.property?.type === "Identifier" &&
      (obj.property.name === "document" || obj.property.name === "ownerDocument"));
  if (!isDoc) return false;
  const tag = staticString(node.arguments?.[0]);
  return typeof tag === "string" && tag.toLowerCase() === "script";
}

/** Identifiers bound by a declaration/parameter pattern. */
function patternNames(pattern: any, out: string[] = []): string[] {
  if (!pattern) return out;
  switch (pattern.type) {
    case "Identifier": out.push(pattern.name); break;
    case "ObjectPattern":
      for (const p of pattern.properties ?? []) patternNames(p.type === "RestElement" ? p.argument : p.value, out);
      break;
    case "ArrayPattern": for (const e of pattern.elements ?? []) patternNames(e, out); break;
    case "AssignmentPattern": patternNames(pattern.left, out); break;
    case "RestElement": patternNames(pattern.argument, out); break;
    case "TSParameterProperty": patternNames(pattern.parameter, out); break;
  }
  return out;
}

/** Names bound ONLY to document.createElement("script") anywhere in the file. */
function scriptElementNames(ast: any): Set<string> {
  const script = new Set<string>();
  const other = new Set<string>();
  walk(ast, (node) => {
    if (node.type === "VariableDeclarator") {
      if (node.id?.type === "Identifier" && isScriptCreate(node.init)) script.add(node.id.name);
      else if (node.init) patternNames(node.id).forEach((n) => other.add(n));
    } else if (node.type === "AssignmentExpression" && node.left?.type === "Identifier") {
      if (node.operator === "=" && isScriptCreate(node.right)) script.add(node.left.name);
      else other.add(node.left.name);
    } else if (node.type === "AssignmentExpression" && node.left?.type !== "MemberExpression") {
      patternNames(node.left).forEach((n) => other.add(n)); // destructuring assignment
    } else if (
      node.type === "FunctionDeclaration" || node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression" || node.type === "ObjectMethod" || node.type === "ClassMethod"
    ) {
      if (node.id?.type === "Identifier") other.add(node.id.name);
      for (const p of node.params ?? []) patternNames(p).forEach((n) => other.add(n));
    } else if (node.type === "ClassDeclaration" && node.id?.type === "Identifier") {
      other.add(node.id.name);
    } else if (node.type === "CatchClause") {
      patternNames(node.param).forEach((n) => other.add(n));
    } else if (node.type === "ForInStatement" || node.type === "ForOfStatement") {
      const left = node.left?.type === "VariableDeclaration" ? node.left.declarations?.[0]?.id : node.left;
      patternNames(left).forEach((n) => other.add(n));
    } else if (
      node.type === "ImportSpecifier" || node.type === "ImportDefaultSpecifier" || node.type === "ImportNamespaceSpecifier"
    ) {
      if (node.local?.type === "Identifier") other.add(node.local.name);
    } else if (node.type === "UpdateExpression" && node.argument?.type === "Identifier") {
      other.add(node.argument.name);
    }
  });
  for (const n of other) script.delete(n);
  return script;
}

interface ScriptSrcSet {
  node: any;
  /** the expression assigned to src */
  value: any;
  how: string;
}

/** Every place a `document.createElement("script")` element gets its `src` set,
 *  literal or not: `.src =`, `["src"] =`, `setAttribute("src", …)`,
 *  `Object.assign(el, { src })`. Shared by MV3001 (literal remote URL) and
 *  MV3005 (computed URL = latent loader). */
function scriptSrcSets(ast: any): ScriptSrcSet[] {
  const names = scriptElementNames(ast);
  const isScriptEl = (node: any): boolean =>
    isScriptCreate(node) || (node?.type === "Identifier" && names.has(node.name));
  const out: ScriptSrcSet[] = [];
  walk(ast, (node) => {
    // <el>.src = …  /  <el>["src"] = …
    if (node.type === "AssignmentExpression" && node.operator === "=" && node.left?.type === "MemberExpression") {
      const left = node.left;
      const prop = left.computed ? staticString(left.property) : left.property?.type === "Identifier" ? left.property.name : null;
      if (prop === "src" && isScriptEl(left.object)) out.push({ node, value: node.right, how: ".src assignment" });
    }
    if (node.type === "CallExpression" && node.callee?.type === "MemberExpression" && !node.callee.computed) {
      const method = node.callee.property?.type === "Identifier" ? node.callee.property.name : null;
      // <el>.setAttribute("src", …)
      if (method === "setAttribute" && isScriptEl(node.callee.object)) {
        const attr = staticString(node.arguments?.[0]);
        if (attr?.toLowerCase() === "src" && node.arguments?.[1]) {
          out.push({ node, value: node.arguments[1], how: 'setAttribute("src")' });
        }
      }
      // Object.assign(<el>, { src: … })
      if (
        method === "assign" &&
        node.callee.object?.type === "Identifier" &&
        node.callee.object.name === "Object" &&
        isScriptEl(node.arguments?.[0])
      ) {
        for (const src of node.arguments.slice(1)) {
          if (src?.type !== "ObjectExpression") continue;
          for (const p of src.properties ?? []) {
            if (p.type !== "ObjectProperty") continue;
            const key = p.computed ? staticString(p.key) : p.key?.type === "Identifier" ? p.key.name : staticString(p.key);
            if (key === "src") out.push({ node, value: p.value, how: "Object.assign({ src })" });
          }
        }
      }
    }
  });
  return out;
}

function injectedRemoteScripts(file: string, ast: any): Finding[] {
  const findings: Finding[] = [];
  for (const { node, value, how } of scriptSrcSets(ast)) {
    const url = staticString(value);
    if (!isRemote(url)) continue;
    findings.push({
      ruleId: "MV3001",
      severity: "reject",
      confidence: "high",
      title: "Remotely hosted code injected via a <script> element",
      message: `${how} points a dynamically created <script> element at "${url}", which loads and runs remote code. Manifest V3 forbids remotely hosted code.`,
      file,
      line: node.loc?.start.line,
      column: node.loc?.start.column,
      chromeViolationId: "Blue Argon",
      fixHint:
        "Bundle the script in the extension package and inject the packaged copy (chrome.runtime.getURL(...) or chrome.scripting.executeScript({ files: [...] })). Fetching remote JSON/data is allowed; only executing remote code is Blue Argon.",
    });
  }
  return findings;
}

// --- chrome.scripting with remote files ------------------------------------
// `chrome.scripting.executeScript({ files: ["https://…"] })` and
// `chrome.scripting.registerContentScripts([{ js: ["https://…"] }])` (also
// updateContentScripts, and the browser.* namespace) name remote code as the
// thing to inject. Only literal http(s):// or protocol-relative entries are
// judged; local paths and computed entries are left alone. CSS entries are not
// code and are not judged.
const SCRIPTING_METHODS = new Set(["executeScript", "registerContentScripts", "updateContentScripts"]);

function scriptingMethod(callee: any): string | null {
  if (callee?.type !== "MemberExpression" && callee?.type !== "OptionalMemberExpression") return null;
  if (callee.computed || callee.property?.type !== "Identifier" || !SCRIPTING_METHODS.has(callee.property.name)) return null;
  const obj = callee.object;
  if ((obj?.type !== "MemberExpression" && obj?.type !== "OptionalMemberExpression") || obj.computed) return null;
  if (obj.property?.type !== "Identifier" || obj.property.name !== "scripting") return null;
  return callee.property.name;
}

function objectProp(obj: any, name: string): any {
  if (obj?.type !== "ObjectExpression") return undefined;
  for (const p of obj.properties ?? []) {
    if (p.type !== "ObjectProperty") continue;
    const key = p.computed ? staticString(p.key) : p.key?.type === "Identifier" ? p.key.name : staticString(p.key);
    if (key === name) return p.value;
  }
  return undefined;
}

function remoteScriptingFiles(file: string, ast: any): Finding[] {
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return;
    const method = scriptingMethod(node.callee);
    if (!method) return;
    const arg = node.arguments?.[0];
    const lists: any[] = [];
    if (method === "executeScript") lists.push(objectProp(arg, "files"));
    else if (arg?.type === "ArrayExpression") for (const el of arg.elements ?? []) lists.push(objectProp(el, "js"));
    for (const list of lists) {
      if (list?.type !== "ArrayExpression") continue;
      for (const el of list.elements ?? []) {
        const url = staticString(el);
        if (!isRemote(url)) continue;
        const key = method === "executeScript" ? "files" : "js";
        findings.push({
          ruleId: "MV3001",
          severity: "reject",
          confidence: "high",
          title: "Remotely hosted code passed to chrome.scripting",
          message: `scripting.${method}() lists "${url}" in ${key}, which injects code from a remote URL. Manifest V3 forbids remotely hosted code (and Chrome only accepts files packaged with the extension here).`,
          file,
          line: el.loc?.start.line ?? node.loc?.start.line,
          column: el.loc?.start.column,
          chromeViolationId: "Blue Argon",
          fixHint: `Bundle the script in the extension package and list its packaged path in ${key} (e.g. "scripts/content.js").`,
        });
      }
    }
  });
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

// --- MV3005: latent remote-code loaders ------------------------------------
// Review judges what bundled code *could* do, not just what it does by default
// (e.g. a shared widget that can inject an rrweb recorder <script> it never
// uses still drew a Blue Argon rejection). MV3005 surfaces that tier without
// condemning it, so it ships at `fix` / `info`, never `reject`:
//  (a) `fix`: a createElement("script") element (or importScripts) is given a
//      COMPUTED src, and either the expression starts with a remote URL prefix
//      (`"https://cdn/" + v`, `` `https://cdn/${v}.js` ``) or the same file also
//      contains a remote `.js`/`.mjs` URL string literal;
//  (b) `info`: remote `.js`/`.mjs` URL string literals in shipped JS that no
//      MV3001/MV3005 finding already explains (one finding per file).
// Precision: only URLs whose path ends in .js/.mjs count, so remote JSON/data
// endpoints, images and pages are never flagged; chrome.runtime.getURL(...)
// sources are local; literal remote srcs are MV3001's job.
const REMOTE_JS_RE = /^(?:https?:)?\/\/[^\s"'`<>()]+\.m?js(?:[?#][^\s"'`<>]*)?$/i;

// Links to a source-code *page* (GitHub/GitLab/Bitbucket blob/tree views) are documentation, not scripts.
const SOURCE_VIEWER_RE = /^(?:https?:)?\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[^?#]*\/(?:blob|tree|src)\//i;

function isRemoteJsUrl(v: unknown): v is string {
  return typeof v === "string" && v.length < 2048 && REMOTE_JS_RE.test(v) && !SOURCE_VIEWER_RE.test(v);
}

/** chrome|browser.runtime.getURL(...) / .extension.getURL(...) → a packaged file. */
function isGetUrlCall(node: any): boolean {
  if (node?.type !== "CallExpression") return false;
  const c = node.callee;
  return (
    c?.type === "MemberExpression" && !c.computed &&
    c.property?.type === "Identifier" && c.property.name === "getURL" &&
    c.object?.type === "MemberExpression" && !c.object.computed &&
    c.object.property?.type === "Identifier" &&
    (c.object.property.name === "runtime" || c.object.property.name === "extension")
  );
}

/** Leading static text of a string-building expression ("a" + x, `a${x}`). */
function staticPrefix(node: any): string | null {
  if (node?.type === "StringLiteral") return node.value;
  if (node?.type === "TemplateLiteral") return node.quasis?.[0]?.value?.cooked ?? null;
  if (node?.type === "BinaryExpression" && node.operator === "+") return staticPrefix(node.left);
  return null;
}

const BANNER_RE = /^\s*(?:\/\*[!*]?|\/\/)\s*(?:@license\s+)?(@?[A-Za-z][\w./-]*)\s+v?(\d+\.\d+\.\d+[\w.-]*)/;
const VENDOR_DIR_RE = /(?:^|\/)(?:vendor|vendors|third[_-]?party|lib|libs)\/([^/]+?)(?:\.min)?\.m?js$/i;

/** Best-effort name of the bundled package a file comes from (banner or vendor path). */
export function probablePackage(relPath: string, content: string): string | null {
  const b = BANNER_RE.exec(content.slice(0, 1000));
  if (b) return `${b[1]}@${b[2]}`;
  const v = VENDOR_DIR_RE.exec(relPath);
  return v ? v[1] : null;
}

function remoteJsLiterals(ast: any): { url: string; line?: number }[] {
  const out: { url: string; line?: number }[] = [];
  walk(ast, (node) => {
    const v = node.type === "StringLiteral" || node.type === "TemplateLiteral" ? staticString(node) : null;
    if (isRemoteJsUrl(v)) out.push({ url: v, line: node.loc?.start.line });
  });
  return out;
}

function mv3005(model: ExtensionModel): Finding[] {
  const findings: Finding[] = [];
  const explained = new Set<string>(); // file\0url already covered by MV3001
  for (const f of mv3001(model)) {
    if (!f.file) continue;
    for (const m of f.message.matchAll(/"([^"]+)"/g)) explained.add(`${f.file}\0${m[1]}`);
  }

  for (const script of model.scriptFiles) {
    if (!script.ast) continue;
    const file = script.relPath;
    const literals = remoteJsLiterals(script.ast).filter((l) => !explained.has(`${file}\0${l.url}`));
    const urls = [...new Set(literals.map((l) => l.url))];
    const pkg = probablePackage(file, script.content);
    const from = pkg ? ` This file looks like bundled code from ${pkg}.` : "";
    const list = (u: string[]) => u.slice(0, 3).map((x) => `"${x}"`).join(", ") + (u.length > 3 ? ` (+${u.length - 3} more)` : "");

    const sinks: { node: any; value: any; how: string }[] = scriptSrcSets(script.ast).filter(
      (s) => staticString(s.value) === null,
    );
    walk(script.ast, (node) => {
      if (node.type === "CallExpression" && isImportScriptsCallee(node.callee)) {
        for (const arg of node.arguments ?? []) {
          if (staticString(arg) === null && arg.type !== "SpreadElement") sinks.push({ node, value: arg, how: "importScripts()" });
        }
      }
    });

    // One `fix` finding per file (first loader), other loader lines listed, to keep bundles readable.
    let latent = false;
    const hits: { node: any; message: string }[] = [];
    for (const { node, value, how } of sinks) {
      if (isGetUrlCall(value)) continue;
      const prefix = staticPrefix(value);
      if (isRemote(prefix)) {
        hits.push({ node, message: `${how} loads a script from a URL built at runtime on the remote prefix "${prefix}". Even if this path never runs, reviewers treat it as remotely hosted code.` });
      } else if (urls.length > 0) {
        latent = true;
        hits.push({ node, message: `${how} loads a script from a computed URL, and this file also contains the remote script URL ${list(urls)}. Review checks what bundled code could do, so this latent loader can draw a Blue Argon rejection even if it never runs.` });
      }
    }
    if (hits.length > 0) {
      hits.sort((a, b) => (a.node.loc?.start.index ?? 0) - (b.node.loc?.start.index ?? 0));
      const first = hits[0];
      const more = [...new Set(hits.slice(1).map((h) => h.node.loc?.start.line).filter((l) => l !== undefined && l !== first.node.loc?.start.line))];
      const also = more.length ? ` Other script loads in this file: line${more.length > 1 ? "s" : ""} ${more.slice(0, 10).join(", ")}${more.length > 10 ? ", …" : ""}.` : "";
      findings.push({
        ruleId: "MV3005",
        severity: "fix",
        confidence: "medium",
        title: "Latent remote-code loader",
        message: first.message + also + from,
        file,
        line: first.node.loc?.start.line,
        column: first.node.loc?.start.column,
        chromeViolationId: "Blue Argon",
        fixHint:
          "If the extension never needs this loader, strip or stub it at build time (or configure the package not to include it) and mention it in the submission notes. If it is needed, bundle the script and load the packaged copy via chrome.runtime.getURL(...). Fetching remote JSON/data is fine.",
      });
    }

    if (!latent && urls.length > 0) {
      findings.push({
        ruleId: "MV3005",
        severity: "info",
        confidence: "low",
        title: "Remote script URL in shipped code",
        message: `Shipped code contains the remote script URL ${list(urls)}. No loader was found for it, but reviewers search bundles for remote .js URLs; check that nothing can load it.${from}`,
        file,
        line: literals[0]?.line,
        chromeViolationId: "Blue Argon",
        fixHint: "Remove unused remote script URLs at build time, or explain them in the submission notes.",
      });
    }
  }
  return findings;
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

export const mv3Rules = [mv3001, mv3002, mv3003, mv3004, mv3005];
