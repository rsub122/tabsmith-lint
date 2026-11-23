import type { ExtensionModel, Finding, Severity } from "../engine/model.js";
import { walk } from "../parse/parse-script.js";
import { findLineByIndex } from "../engine/source-lines.js";

// OBF001 — obfuscated code (Chrome Web Store "Red Titanium"). Google's policy:
// minification is allowed, obfuscation is not ("character encoding", hidden
// functionality, packers). Minified bundles look nothing like obfuscator output,
// so OBF001 only fires on fingerprints that minifiers never produce:
//  - `_0x`-style hexadecimal identifiers (javascript-obfuscator / obfuscator.io)
//    used in quantity;
//  - a string-array rotator: `arr.push(arr.shift())` inside a function that also
//    runs the obfuscator's parseInt checksum or a `while (--n)` countdown;
//  - string-array lookups: one function called over and over with a hex numeric
//    literal (`_0x1a2b(0x1f4)`), the decoder call that replaces every string;
//  - a Dean Edwards packer: `eval(function(p,a,c,k,e,d){…}(…))`;
//  - eval / Function run on a decoded payload: `eval(atob(…))`,
//    `new Function(String.fromCharCode(…))`, `eval(unescape(…))`;
//  - plain-ASCII text hidden behind escapes: many string literals written as
//    `"\x68\x65\x6c\x6c\x6f"` (minifiers only escape non-printable/non-ASCII).
// Thresholds were set on a negative set of 40+ popular minified npm libraries
// (lodash, react-dom, vue, chart.js, three, pdf.js, @babel/standalone, crypto
// libraries, ...) plus the minified release corpus, where OBF001 reports nothing.
// Severity is `fix`, not `reject`: the finding names what to replace and is a
// strong signal, but static fingerprints cannot prove intent. One finding per file.
export const OBF001_SEVERITY: Severity = "fix";

/** Minimum distinct `_0x…` identifiers for the identifier signal. */
export const HEX_IDENT_MIN = 10;
/** Minimum calls of a single function with a small hex index literal argument… */
export const HEX_LOOKUP_MIN = 25;
/** …with at least this many distinct index values. */
export const HEX_LOOKUP_DISTINCT_MIN = 15;
/** Minimum string literals that are plain ASCII text spelled with escapes. */
export const ESCAPED_ASCII_MIN = 20;

const HEX_IDENT_RE = /^_0x[0-9a-f]{3,}$/i;
const DECODERS = new Set(["atob", "unescape", "decodeURIComponent", "decodeURI", "escape"]);

export interface ObfuscationSignals {
  hexIdentifiers: number;
  rotator: boolean;
  hexLookupCalls: number;
  hexLookupCallee: string | null;
  packer: boolean;
  decodedEval: string | null;
  escapedAsciiStrings: number;
  /** character offset of the first strong signal (for the line number / package lookup) */
  firstIndex: number | null;
}

function propName(member: any): string | null {
  if (member?.type !== "MemberExpression" && member?.type !== "OptionalMemberExpression") return null;
  if (!member.computed) return member.property?.type === "Identifier" ? member.property.name : null;
  return member.property?.type === "StringLiteral" ? member.property.value : null;
}

/** `A.push(A.shift())` / `A['push'](A['shift']())` with the same identifier A. */
function isPushShift(node: any): boolean {
  if (node?.type !== "CallExpression" || propName(node.callee) !== "push") return false;
  const obj = node.callee.object;
  const arg = node.arguments?.[0];
  if (obj?.type !== "Identifier" || node.arguments.length !== 1) return false;
  return (
    arg?.type === "CallExpression" &&
    propName(arg.callee) === "shift" &&
    arg.callee.object?.type === "Identifier" &&
    arg.callee.object.name === obj.name &&
    (arg.arguments?.length ?? 0) === 0
  );
}

function isFunctionNode(node: any): boolean {
  return node?.type === "FunctionDeclaration" || node?.type === "FunctionExpression" || node?.type === "ArrowFunctionExpression";
}

/** A function body that rotates an array AND runs a checksum (parseInt ×2) or a `while (--n)` countdown. */
function isRotatorFunction(fn: any): boolean {
  let pushShift = false;
  let parseInts = 0;
  let countdown = false;
  walk(fn.body, (n) => {
    if (isPushShift(n)) pushShift = true;
    else if (n.type === "CallExpression" && n.callee?.type === "Identifier" && n.callee.name === "parseInt") parseInts++;
    else if (n.type === "WhileStatement" && n.test?.type === "UpdateExpression" && n.test.operator === "--") countdown = true;
  });
  return pushShift && (parseInts >= 2 || countdown);
}

// String-array decoder call: `_0x1a2b(0x1f4)` / `_0x1a2b(0x1f4, "key")`. The index is
// a small, lower-case, unpadded hex literal (< 0x10000). Colour and hash constants
// (0xffb845, 0x428a2f98) are larger, so crypto/graphics code doesn't count.
const LOOKUP_HEX_RE = /^0x(?:0|[1-9a-f][0-9a-f]{0,3})$/;

function isHexLookup(node: any): boolean {
  if (node.callee?.type !== "Identifier") return false;
  const args = node.arguments ?? [];
  if (args.length !== 1 && args.length !== 2) return false;
  if (args[0]?.type !== "NumericLiteral" || !LOOKUP_HEX_RE.test(args[0].extra?.raw ?? "")) return false;
  return args.length === 1 || ["StringLiteral", "NumericLiteral", "UnaryExpression"].includes(args[1]?.type);
}

/** `eval(function(p,a,c,k,e,d){…}(…))` — Dean Edwards' packer. */
function isPacker(node: any): boolean {
  if (node?.type !== "CallExpression" || node.callee?.type !== "Identifier" || node.callee.name !== "eval") return false;
  const inner = node.arguments?.[0];
  if (inner?.type !== "CallExpression" || !isFunctionNode(inner.callee)) return false;
  const names = (inner.callee.params ?? []).map((p: any) => (p.type === "Identifier" ? p.name : "?")).join(",");
  return /^p,a,c,k,e,[a-z]$/.test(names);
}

/** A decoding call: atob(...), unescape(...), String.fromCharCode(...), possibly nested. */
function decoderName(node: any): string | null {
  if (node?.type !== "CallExpression") return null;
  const c = node.callee;
  if (c?.type === "Identifier" && DECODERS.has(c.name)) return `${c.name}()`;
  if (
    (c?.type === "MemberExpression") && propName(c) === "fromCharCode" &&
    c.object?.type === "Identifier" && c.object.name === "String"
  ) return "String.fromCharCode()";
  return null;
}

/** eval(<decoded>), Function(<decoded>), new Function(<decoded>) → the decoder it wraps. */
function decodedEvalOf(node: any): string | null {
  const isCall = node?.type === "CallExpression" || node?.type === "NewExpression";
  if (!isCall || node.callee?.type !== "Identifier") return null;
  const name = node.callee.name;
  if (name !== "eval" && name !== "Function") return null;
  if (name === "eval" && node.type === "NewExpression") return null;
  // the code argument is the first for eval and the last for Function
  const args = node.arguments ?? [];
  const code = name === "eval" ? args[0] : args[args.length - 1];
  const dec = decoderName(code);
  return dec ? `${node.type === "NewExpression" ? "new " : ""}${name}(${dec})` : null;
}

const ESCAPE_RE = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}/g;

/** A string literal whose source spells printable ASCII text with escapes ("\x68\x69"). */
function isEscapedAscii(node: any): boolean {
  if (node?.type !== "StringLiteral") return false;
  const raw: string | undefined = node.extra?.raw;
  const value: string = node.value;
  if (!raw || value.length < 3) return false;
  if (!/^[\x20-\x7e]+$/.test(value) || !/[A-Za-z]/.test(value)) return false;
  let escapedChars = 0;
  let escapes = 0;
  for (const m of raw.matchAll(ESCAPE_RE)) {
    const ch = m[0].startsWith("\\x") ? parseInt(m[0].slice(2), 16) : parseInt(m[0].replace(/[\\u{}]/g, ""), 16);
    if (ch >= 0x20 && ch <= 0x7e) { escapes++; escapedChars += m[0].length; }
  }
  return escapes >= 3 && escapedChars >= (raw.length - 2) * 0.75;
}

/** Raw obfuscation measurements for one parsed file (exported for tests and FP probes). */
export function obfuscationSignals(ast: any): ObfuscationSignals {
  const hexIds = new Set<string>();
  const lookups = new Map<string, { calls: number; values: Set<number> }>();
  let rotator = false;
  let packer = false;
  let decodedEval: string | null = null;
  let escapedAscii = 0;
  let firstIndex: number | null = null;
  const mark = (n: any) => {
    const i = n?.start;
    if (typeof i === "number" && (firstIndex === null || i < firstIndex)) firstIndex = i;
  };
  let firstHexId: any = null;
  let firstEscaped: any = null;
  const firstLookup = new Map<string, any>();
  const functions: any[] = [];
  const pushShifts: number[] = [];

  walk(ast, (node) => {
    switch (node.type) {
      case "Identifier":
        if (HEX_IDENT_RE.test(node.name)) {
          hexIds.add(node.name);
          if (!firstHexId) firstHexId = node;
        }
        break;
      case "StringLiteral":
        if (isEscapedAscii(node)) {
          escapedAscii++;
          if (!firstEscaped) firstEscaped = node;
        }
        break;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        functions.push(node);
        break;
      case "CallExpression":
      case "NewExpression": {
        if (isPushShift(node)) pushShifts.push(node.start);
        if (node.type === "CallExpression" && isPacker(node)) { packer = true; mark(node); }
        const de = decodedEvalOf(node);
        if (de && !decodedEval) { decodedEval = de; mark(node); }
        if (node.type === "CallExpression" && isHexLookup(node)) {
          const name = node.callee.name;
          const e = lookups.get(name) ?? { calls: 0, values: new Set<number>() };
          e.calls++;
          e.values.add(node.arguments[0].value);
          lookups.set(name, e);
          if (!firstLookup.has(name)) firstLookup.set(name, node);
        }
        break;
      }
    }
  });

  // Rotator check: only the INNERMOST function around each arr.push(arr.shift())
  // (rare in real code; an outer bundle wrapper would contain unrelated parseInt calls).
  for (const at of pushShifts) {
    let inner: any = null;
    for (const fn of functions) if (fn.start < at && at < fn.end && (!inner || fn.start > inner.start)) inner = fn;
    if (inner && isRotatorFunction(inner)) { rotator = true; mark(inner); break; }
  }

  let hexLookupCalls = 0;
  let hexLookupCallee: string | null = null;
  for (const [name, e] of lookups) {
    // a decoder is called with many DIFFERENT indices; constant tables repeat a few values
    if (e.values.size >= HEX_LOOKUP_DISTINCT_MIN && e.calls > hexLookupCalls) { hexLookupCalls = e.calls; hexLookupCallee = name; }
  }
  if (hexIds.size >= HEX_IDENT_MIN) mark(firstHexId);
  if (hexLookupCalls >= HEX_LOOKUP_MIN) mark(firstLookup.get(hexLookupCallee!));
  if (escapedAscii >= ESCAPED_ASCII_MIN) mark(firstEscaped);

  return {
    hexIdentifiers: hexIds.size,
    rotator,
    hexLookupCalls,
    hexLookupCallee,
    packer,
    decodedEval,
    escapedAsciiStrings: escapedAscii,
    firstIndex,
  };
}

/** Human-readable list of the signals that crossed their thresholds (empty = not obfuscated). */
export function signalReasons(s: ObfuscationSignals): string[] {
  const out: string[] = [];
  if (s.packer) out.push("a Dean Edwards packer (eval(function(p,a,c,k,e,d){…}))");
  if (s.decodedEval) out.push(`code executed from a decoded string (${s.decodedEval})`);
  if (s.rotator) out.push("a string-array rotator (arr.push(arr.shift()) with a checksum loop)");
  if (s.hexIdentifiers >= HEX_IDENT_MIN) out.push(`${s.hexIdentifiers} _0x-style hexadecimal identifiers`);
  if (s.hexLookupCalls >= HEX_LOOKUP_MIN) out.push(`${s.hexLookupCalls} string-array lookups (${s.hexLookupCallee}(0x…))`);
  if (s.escapedAsciiStrings >= ESCAPED_ASCII_MIN) out.push(`${s.escapedAsciiStrings} plain-text strings spelled with \\x/\\u escapes`);
  return out;
}

const BANNER_RE = /^\s*(?:\/\*[!*]?|\/\/)\s*(?:@license\s+)?(@?[A-Za-z][\w./-]*)\s+v?(\d+\.\d+\.\d+[\w.-]*)/;
const NODE_MODULES_RE = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/g;
const VENDOR_RE = /(?:^|\/)(?:vendor|vendors|third[_-]?party|libs?)\/([^/]+?)(?:(?:\.min)?\.[cm]?js$|\/)/i;
// Module-path comments bundlers leave between modules: esbuild/rollup `// node_modules/x/index.js`,
// webpack `/***/ "./node_modules/x/index.js":` and `// CONCATENATED MODULE: ./src/a.js`.
const MODULE_MARKER_RE = /(?:^|\n)[ \t]*(?:\/\/|\/\*{1,3}\/)[ \t]*(?:CONCATENATED MODULE:[ \t]*)?["']?((?:\.{1,2}\/)?[\w@.+-]+(?:\/[\w@.+-]+)+\.[cm]?[jt]sx?)/g;
const PKG_IN_PATH_RE = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\/(?!.*node_modules\/)/;

/** Best-effort name of the bundled npm package the obfuscated code comes from:
 *  a license banner, a node_modules/ path, a vendor/ path, or the nearest
 *  `node_modules/<pkg>` module-path comment before the obfuscated code in a bundle. */
export function bundledPackageName(relPath: string, content: string, index: number | null = null): string | null {
  const b = BANNER_RE.exec(content.slice(0, 1000));
  if (b) return `${b[1]}@${b[2]}`;
  const nm = [...relPath.matchAll(NODE_MODULES_RE)];
  if (nm.length) return nm[nm.length - 1][1];
  const v = VENDOR_RE.exec(relPath);
  if (v) return v[1];
  if (index !== null && index > 0) {
    const before = content.slice(Math.max(0, index - 200_000), index);
    // Only the NEAREST module marker counts: if it is first-party (./src/...), don't blame a package.
    const markers = [...before.matchAll(MODULE_MARKER_RE)];
    const last = markers.length ? markers[markers.length - 1][1] : null;
    const pkg = last ? PKG_IN_PATH_RE.exec(last) : null;
    if (pkg) return pkg[1];
  }
  return null;
}

function obf001(model: ExtensionModel): Finding[] {
  const findings: Finding[] = [];
  for (const script of model.scriptFiles) {
    if (!script.ast) continue;
    const s = obfuscationSignals(script.ast);
    const reasons = signalReasons(s);
    if (reasons.length === 0) continue;
    const pkg = bundledPackageName(script.relPath, script.content, s.firstIndex);
    const from = pkg ? ` It looks like it comes from the bundled package ${pkg}.` : "";
    findings.push({
      ruleId: "OBF001",
      severity: OBF001_SEVERITY,
      confidence: reasons.length > 1 || s.packer || s.rotator ? "high" : "medium",
      title: "Obfuscated code",
      message: `This file shows obfuscation fingerprints: ${reasons.join("; ")}. The Chrome Web Store rejects obfuscated code (Red Titanium); minification is allowed, obfuscation is not.${from}`,
      file: script.relPath,
      line: s.firstIndex !== null ? findLineByIndex(script.content, s.firstIndex) : undefined,
      chromeViolationId: "Red Titanium",
      fixHint: pkg
        ? `Replace ${pkg} with a non-obfuscated build (or another package), or ask its maintainer for readable source. Minified code is fine.`
        : "Ship this code minified instead of obfuscated (drop javascript-obfuscator/packer steps from the build). Minified code is fine.",
    });
  }
  return findings;
}

export const obfuscationRules = [obf001];
