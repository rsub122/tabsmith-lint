// High-frequency Chrome permission → API namespace map (PRD 6.6). Not exhaustive
// by design; unknown permissions are simply not mapped (no false unused finding).

export interface PermMapping {
  namespace?: string;
  requiresHostPermission?: boolean;
  special?: "sensitiveTabProperties" | "temporaryHostAccess";
}

// Null-prototype throughout: namespace/permission keys come from parsed code, so
// a lookup like map["constructor"] must not resolve to an inherited Object member.
export const chromePermissionMap: Record<string, PermMapping> = Object.assign(Object.create(null), {
  storage: { namespace: "storage" },
  scripting: { namespace: "scripting" },
  cookies: { namespace: "cookies", requiresHostPermission: true },
  bookmarks: { namespace: "bookmarks" },
  alarms: { namespace: "alarms" },
  notifications: { namespace: "notifications" },
  contextMenus: { namespace: "contextMenus" },
  webRequest: { namespace: "webRequest", requiresHostPermission: true },
  declarativeNetRequest: { namespace: "declarativeNetRequest" },
  downloads: { namespace: "downloads" },
  history: { namespace: "history" },
  identity: { namespace: "identity" },
  management: { namespace: "management" },
  tabs: { special: "sensitiveTabProperties" },
  activeTab: { special: "temporaryHostAccess" },
});

/** namespace → permission required to use it (PERM002). Only namespaces whose
 *  use genuinely requires a permission. `tabs` is intentionally excluded: the
 *  tabs namespace methods don't require the `tabs` permission (PRD §5 PERM002). */
export const namespaceToPermission: Record<string, string> = (() => {
  const out: Record<string, string> = Object.create(null);
  for (const [perm, mapping] of Object.entries(chromePermissionMap)) {
    if (mapping.namespace) out[mapping.namespace] = perm;
  }
  return out;
})();

/** Some namespaces are granted by more than one permission string. Declaring
 *  ANY of these satisfies PERM002 for that namespace. (Real extensions commonly
 *  use declarativeNetRequestWithHostAccess instead of the base permission.) */
export const namespacePermissionAliases: Record<string, string[]> = Object.assign(Object.create(null), {
  declarativeNetRequest: [
    "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess",
    "declarativeNetRequestFeedback",
  ],
});

/** All permission strings that satisfy a namespace's PERM002 requirement. */
export function permissionsForNamespace(namespace: string): string[] {
  if (namespacePermissionAliases[namespace]) return namespacePermissionAliases[namespace];
  const p = namespaceToPermission[namespace];
  return p ? [p] : [];
}

/** Broad host match patterns that trigger PERM003/004/005. */
export const BROAD_HOST_PATTERNS = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"];

export function isBroadHost(pattern: string): boolean {
  return BROAD_HOST_PATTERNS.includes(pattern);
}
