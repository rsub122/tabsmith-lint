import type { ExtensionModel, Finding, Severity, Confidence } from "../engine/model.js";
import { chromePermissionMap, namespaceToPermission, permissionsForNamespace, isBroadHost } from "../data/chrome-permission-map.js";
import { findLine } from "../engine/source-lines.js";

// KTD 3: PERM001 ships at `fix`, NEVER `reject`, in v0.1. The flagship rule's
// false-positive rate is make-or-break ("trust is the product"). Promote to
// "reject" only after validating against a hand-labeled corpus (deferred).
// This is the single config point — change here, nowhere else.
export const PERM001_SEVERITY: Severity = "fix";

// Manifests are loosely typed (only manifest_version is validated on load), so a
// well-formed-JSON manifest can carry a non-array where an array is expected.
// Coerce defensively — never spread an arbitrary value.
const asArray = (x: unknown): string[] => (Array.isArray(x) ? (x as string[]) : []);

function declaredPermissions(m: ExtensionModel["manifest"]): string[] {
  return [...asArray(m.permissions), ...asArray(m.optional_permissions)];
}

function hostPatterns(m: ExtensionModel["manifest"]): string[] {
  const out = [...asArray(m.host_permissions)];
  const cs = (m as any).content_scripts;
  if (Array.isArray(cs)) {
    for (const entry of cs) out.push(...asArray(entry?.matches));
  }
  return out;
}

function hasBroadHost(m: ExtensionModel["manifest"]): boolean {
  return hostPatterns(m).some(isBroadHost);
}

function hasGestureEntryPoint(m: ExtensionModel["manifest"], declared: string[]): boolean {
  const mm = m as any;
  return Boolean(mm.action || mm.browser_action || mm.commands || mm.context_menus) || declared.includes("contextMenus");
}

// Some permissions are exercised declaratively via the manifest rather than by a
// JS API call. declarativeNetRequest is the common case: an extension can ship
// static rulesets (declarative_net_request.rule_resources) and never touch the
// chrome.declarativeNetRequest namespace in code. Counting only code usage would
// produce a false "unused" finding (trust is the product).
function isUsedViaManifest(perm: string, m: ExtensionModel["manifest"]): boolean {
  if (perm === "declarativeNetRequest") return Boolean((m as any).declarative_net_request);
  return false;
}

/** PERM001 — declared permission appears unused. */
function perm001(model: ExtensionModel): Finding[] {
  const { manifest, apiCalls, dynamicApiAccess } = model;
  const declared = declaredPermissions(manifest);
  const broad = hasBroadHost(manifest);
  const dynamicConfidence: Confidence = dynamicApiAccess.length > 0 ? "low" : "high";
  // Permissions asked for at runtime via chrome.permissions.request/contains are
  // used by definition — common for optional_permissions gated behind a user
  // gesture, where the namespace call may be dynamic or in a lazily-loaded module.
  const runtimeRequested = new Set(model.runtimeRequestedPermissions);
  const findings: Finding[] = [];

  for (const perm of declared) {
    const mapping = chromePermissionMap[perm];
    if (!mapping) continue; // unknown permission → no claim (avoid false positives)
    if (runtimeRequested.has(perm)) continue; // requested at runtime → used

    if (mapping.namespace) {
      const used = apiCalls.some((c) => c.namespace === mapping.namespace) || isUsedViaManifest(perm, manifest);
      if (!used) {
        findings.push(unusedFinding(model, perm, dynamicConfidence,
          `No chrome.${mapping.namespace}/browser.${mapping.namespace} usage found.`));
      }
    } else if (mapping.special === "sensitiveTabProperties") {
      // `tabs` is "used" only via sensitive Tab property reads. When broad host
      // is present, redundancy is owned by PERM004 — don't double-flag here.
      if (!broad && model.sensitiveTabReads.length === 0) {
        findings.push(unusedFinding(model, perm, dynamicConfidence,
          `The "tabs" permission only grants sensitive Tab properties (url, title, ...); no such reads were found.`));
      }
    } else if (mapping.special === "temporaryHostAccess") {
      // `activeTab` is plausibly used only behind a user-gesture entry point.
      if (!hasGestureEntryPoint(manifest, declared)) {
        findings.push(unusedFinding(model, perm, "medium",
          `"activeTab" has no user-gesture entry point (action/commands/contextMenus) to trigger it.`));
      }
    }
  }
  return findings;
}

function unusedFinding(model: ExtensionModel, perm: string, confidence: Confidence, message: string): Finding {
  return {
    ruleId: "PERM001",
    severity: PERM001_SEVERITY,
    confidence,
    title: `Permission "${perm}" appears unused`,
    message,
    file: "manifest.json",
    line: findLine(model.manifestRaw, `"${perm}"`),
    chromeViolationId: "Purple Potassium",
    fixHint: `Remove "${perm}" from permissions unless it is required by code not included in this package.`,
  };
}

/** PERM002 — API used but required permission missing. */
function perm002(model: ExtensionModel): Finding[] {
  const declared = new Set(declaredPermissions(model.manifest));
  const findings: Finding[] = [];
  const reported = new Set<string>();

  for (const call of model.apiCalls) {
    if (call.confidence !== "high") continue;
    const perm = namespaceToPermission[call.namespace];
    if (!perm || reported.has(perm)) continue;
    // Any aliased permission string for this namespace satisfies the requirement
    // (e.g. declarativeNetRequestWithHostAccess grants declarativeNetRequest).
    if (permissionsForNamespace(call.namespace).some((p) => declared.has(p))) continue;
    reported.add(perm);
    findings.push({
      ruleId: "PERM002",
      severity: "reject",
      confidence: "high",
      title: `API used without required permission "${perm}"`,
      message: `Code calls ${call.root}.${call.namespace}.* but "${perm}" is not declared in permissions or optional_permissions.`,
      file: call.file,
      line: call.line,
      column: call.column,
      fixHint: `Add "${perm}" to the manifest "permissions" array.`,
    });
  }
  return findings;
}

/** PERM003 — activeTab redundant with broad host permissions. */
function perm003(model: ExtensionModel): Finding[] {
  const declared = declaredPermissions(model.manifest);
  if (!declared.includes("activeTab") || !hasBroadHost(model.manifest)) return [];
  return [{
    ruleId: "PERM003",
    severity: "fix",
    confidence: "high",
    title: `"activeTab" is redundant with broad host permissions`,
    message: `Broad host access already covers what activeTab grants on demand.`,
    file: "manifest.json",
    line: findLine(model.manifestRaw, `"activeTab"`),
    fixHint: `Remove "activeTab" if broad host access is required, or narrow host access and keep "activeTab" for user-gesture access.`,
  }];
}

/** PERM004 — tabs redundant with broad host permissions. */
function perm004(model: ExtensionModel): Finding[] {
  const declared = declaredPermissions(model.manifest);
  if (!declared.includes("tabs") || !hasBroadHost(model.manifest)) return [];
  return [{
    ruleId: "PERM004",
    severity: "fix",
    confidence: "high",
    title: `"tabs" is redundant with broad host permissions`,
    message: `Broad host access already exposes the sensitive Tab data that the "tabs" permission grants.`,
    file: "manifest.json",
    line: findLine(model.manifestRaw, `"tabs"`),
    fixHint: `Remove "tabs" unless the extension must read sensitive tab data outside declared host patterns.`,
  }];
}

/** PERM005 — broad host access requested. */
function perm005(model: ExtensionModel): Finding[] {
  const patterns = hostPatterns(model.manifest);
  const broad = patterns.filter(isBroadHost);
  if (broad.length === 0) return [];
  return [{
    ruleId: "PERM005",
    severity: "fix",
    confidence: "high",
    title: `Broad host access requested`,
    message: `Broad host patterns requested: ${[...new Set(broad)].join(", ")}.`,
    file: "manifest.json",
    line: findLine(model.manifestRaw, broad[0]),
    fixHint: `Replace broad patterns with the narrowest required host patterns.`,
  }];
}

export const permissionRules = [perm001, perm002, perm003, perm004, perm005];
