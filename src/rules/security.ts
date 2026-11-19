import type { ExtensionModel, Finding, Severity } from "../engine/model.js";
import { walk } from "../parse/parse-script.js";
import { findLine } from "../engine/source-lines.js";

// SEC001 — declarativeNetRequest `modifyHeaders` rules that remove or overwrite a
// page's security response headers (CSP, X-Frame-Options, COOP/COEP/CORP, HSTS).
// Stripping these on every site weakens the security of pages the user visits
// "whether or not the extension is in use", which Chrome Web Store reviewers and
// Trust & Safety treat as unexpected/harmful behavior. Deterministic from JSON
// already in the package, so precision is high; severity reflects reach:
//  - `fix`  when the rule's condition is not scoped to specific domains AND the
//           extension has broad host access (modifyHeaders only applies where the
//           extension has host permissions);
//  - `info` when it is scoped (requestDomains/initiatorDomains/tabIds, a
//           domain-anchored urlFilter or a regexFilter naming a domain) or the
//           extension's host access is narrow.
// Sources: static rulesets (declarative_net_request.rule_resources) and literal
// rules passed to updateDynamicRules/updateSessionRules({ addRules: [...] }).
// `append` is not judged (appending a CSP only tightens it); request headers are
// out of scope.
export const SECURITY_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "strict-transport-security",
]);
const JUDGED_OPS = new Set(["remove", "set"]);
const BROAD_HOST_RE = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|https?:\/\/\*\/)$/;
const DOMAIN_ANCHORED_RE = /^(\|\||\|https?:\/\/|https?:\/\/|\*:\/\/)(?!\*)[a-z0-9-]+(\.[a-z0-9-]+)+/i;
const REGEX_DOMAIN_RE = /[a-z0-9-]+\\\.[a-z]{2,}/i;

interface RuleSource {
  file: string;
  rules: unknown;
  /** text to search for line numbers (JSON file or script source) */
  text: string;
  baseLine?: number;
  note?: string;
}

function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function isScoped(cond: any): boolean {
  if (!cond || typeof cond !== "object") return false;
  if (strArr(cond.requestDomains).length || strArr(cond.initiatorDomains).length) return true;
  if (Array.isArray(cond.tabIds) && cond.tabIds.length) return true;
  if (typeof cond.urlFilter === "string" && DOMAIN_ANCHORED_RE.test(cond.urlFilter)) return true;
  if (typeof cond.regexFilter === "string" && REGEX_DOMAIN_RE.test(cond.regexFilter)) return true;
  return false;
}

function hasBroadHostAccess(model: ExtensionModel): boolean {
  const m = model.manifest as any;
  const hosts = [...strArr(m.host_permissions), ...strArr(m.optional_host_permissions)];
  if (model.manifest.manifest_version === 2) hosts.push(...strArr(m.permissions));
  return hosts.some((h) => BROAD_HOST_RE.test(h.trim()));
}

function describeCondition(cond: any): string {
  if (!cond || typeof cond !== "object" || Object.keys(cond).length === 0) return "no condition (every request)";
  if (typeof cond.urlFilter === "string") return `urlFilter "${cond.urlFilter}"`;
  if (typeof cond.regexFilter === "string") return `regexFilter "${cond.regexFilter}"`;
  if (strArr(cond.requestDomains).length) return `requestDomains ${strArr(cond.requestDomains).slice(0, 3).join(", ")}`;
  return "a condition with no URL or domain filter";
}

function judge(model: ExtensionModel, src: RuleSource, broadHosts: boolean): Finding[] {
  if (!Array.isArray(src.rules)) return [];
  const out: Finding[] = [];
  for (const rule of src.rules as any[]) {
    if (!rule || typeof rule !== "object" || rule.action?.type !== "modifyHeaders") continue;
    const hits = (Array.isArray(rule.action.responseHeaders) ? rule.action.responseHeaders : []).filter(
      (h: any) =>
        typeof h?.header === "string" && SECURITY_HEADERS.has(h.header.toLowerCase()) && JUDGED_OPS.has(h.operation),
    );
    if (hits.length === 0) continue;
    const scoped = isScoped(rule.condition);
    const severity: Severity = !scoped && broadHosts ? "fix" : "info";
    const what = hits.map((h: any) => `${h.operation} ${h.header}`).join(", ");
    const id = rule.id !== undefined ? ` ${rule.id}` : "";
    const reach = scoped
      ? "It is scoped to specific sites; make sure the listing explains why."
      : broadHosts
        ? "The condition is not scoped to specific sites and the extension has broad host access, so it weakens security on every page the user visits, whether or not the extension is in use."
        : "The condition is not scoped to specific sites, but the extension's host access is narrow, which limits where it applies.";
    const line = src.baseLine ?? (rule.id !== undefined ? findIdLine(src.text, rule.id) : undefined) ?? findLine(src.text, hits[0].header);
    out.push({
      ruleId: "SEC001",
      severity,
      confidence: "high",
      title: "declarativeNetRequest rule strips security headers",
      message: `DNR rule${id} uses modifyHeaders to ${what} on ${describeCondition(rule.condition)}. ${reach}${src.note ?? ""} Reviewers treat removing a site's security headers as harmful/unexpected behavior.`,
      file: src.file,
      line,
      fixHint:
        "Scope the rule to the exact domains that need it (condition.requestDomains) and, if possible, only enable it while the feature is in use (updateEnabledRulesets / session rules). Explain the header change in the listing and the submission notes.",
    });
  }
  return out;
}

function findIdLine(text: string, id: unknown): number | undefined {
  const re = new RegExp(`"id"\\s*:\\s*${String(id).replace(/[^\w]/g, "")}\\b`);
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return undefined;
}

/** Convert a fully static AST literal (object/array/string/number/bool/null) to a value; undefined if not static. */
const NOT_STATIC = Symbol("not-static");
function staticValue(node: any): unknown {
  switch (node?.type) {
    case "StringLiteral": return node.value;
    case "NumericLiteral": return node.value;
    case "BooleanLiteral": return node.value;
    case "NullLiteral": return null;
    case "TemplateLiteral":
      return node.expressions?.length === 0 ? node.quasis?.[0]?.value?.cooked : NOT_STATIC;
    case "ArrayExpression": {
      const out: unknown[] = [];
      for (const el of node.elements ?? []) {
        const v = staticValue(el);
        out.push(v === NOT_STATIC ? undefined : v); // keep other entries judgeable
      }
      return out;
    }
    case "ObjectExpression": {
      const out: Record<string, unknown> = {};
      for (const p of node.properties ?? []) {
        if (p.type !== "ObjectProperty") continue;
        const key = p.computed ? staticValue(p.key) : p.key?.type === "Identifier" ? p.key.name : staticValue(p.key);
        if (typeof key !== "string" && typeof key !== "number") continue;
        const v = staticValue(p.value);
        if (v !== NOT_STATIC) out[String(key)] = v;
      }
      return out;
    }
    default: return NOT_STATIC;
  }
}

const DYNAMIC_METHODS = new Set(["updateDynamicRules", "updateSessionRules"]);

export function sec001(model: ExtensionModel): Finding[] {
  const broadHosts = hasBroadHostAccess(model);
  const findings: Finding[] = [];

  for (const rs of model.dnrRulesets) {
    findings.push(...judge(model, {
      file: rs.relPath,
      rules: rs.rules,
      text: rs.content,
      note: rs.enabled ? "" : ` (Ruleset "${rs.id ?? rs.relPath}" is disabled by default but can be enabled at runtime.)`,
    }, broadHosts));
  }

  for (const script of model.scriptFiles) {
    if (!script.ast) continue;
    walk(script.ast, (node) => {
      if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return;
      const c = node.callee;
      if ((c?.type !== "MemberExpression" && c?.type !== "OptionalMemberExpression") || c.computed) return;
      if (c.property?.type !== "Identifier" || !DYNAMIC_METHODS.has(c.property.name)) return;
      const opts = staticValue(node.arguments?.[0]) as any;
      if (!opts || typeof opts !== "object") return;
      findings.push(...judge(model, {
        file: script.relPath,
        rules: opts.addRules,
        text: script.content,
        baseLine: node.loc?.start.line,
        note: ` (Added at runtime via ${c.property.name}().)`,
      }, broadHosts));
    });
  }
  return findings;
}

export const securityRules = [sec001];
