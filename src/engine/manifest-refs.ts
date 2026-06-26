import type { ManifestJson, ManifestFileRef } from "./model.js";

export interface ManifestRefs {
  /** every concrete (non-glob) file reference, for FUNC001/002 + pass-1 discovery */
  all: ManifestFileRef[];
  /** HTML pages referenced by the manifest, for script-src extraction */
  pages: string[];
  /** scripts directly referenced by the manifest */
  scripts: string[];
}

function pushStr(out: ManifestFileRef[], source: string, v: unknown) {
  if (typeof v === "string" && v.length > 0) out.push({ ref: v, source });
}

function pushList(out: ManifestFileRef[], source: string, v: unknown) {
  if (Array.isArray(v)) for (const item of v) pushStr(out, source, item);
}

/** Collect file references from the manifest. Glob entries (containing '*') are
 *  dropped from `all` since they can't be existence-checked. */
export function collectManifestRefs(manifest: ManifestJson): ManifestRefs {
  const all: ManifestFileRef[] = [];
  const pages: string[] = [];
  const scripts: string[] = [];
  const m = manifest as any;

  // background
  pushStr(all, "background.service_worker", m.background?.service_worker);
  if (m.background?.service_worker) scripts.push(m.background.service_worker);
  pushList(all, "background.scripts", m.background?.scripts);
  if (Array.isArray(m.background?.scripts)) scripts.push(...m.background.scripts);

  // content scripts
  if (Array.isArray(m.content_scripts)) {
    for (const cs of m.content_scripts) {
      pushList(all, "content_scripts.js", cs?.js);
      pushList(all, "content_scripts.css", cs?.css);
      if (Array.isArray(cs?.js)) scripts.push(...cs.js);
    }
  }

  // action popup + icons
  pushStr(all, "action.default_popup", m.action?.default_popup ?? m.browser_action?.default_popup);
  const popup = m.action?.default_popup ?? m.browser_action?.default_popup;
  if (typeof popup === "string") pages.push(popup);
  collectIcons(all, "action.default_icon", m.action?.default_icon);
  collectIcons(all, "icons", m.icons);

  // pages
  for (const [key, val] of [
    ["options_page", m.options_page],
    ["options_ui.page", m.options_ui?.page],
    ["devtools_page", m.devtools_page],
    ["side_panel.default_path", m.side_panel?.default_path],
  ] as const) {
    if (typeof val === "string") {
      pushStr(all, key, val);
      if (val.endsWith(".html")) pages.push(val);
    }
  }

  // chrome_url_overrides
  if (m.chrome_url_overrides && typeof m.chrome_url_overrides === "object") {
    for (const [k, v] of Object.entries(m.chrome_url_overrides)) {
      pushStr(all, `chrome_url_overrides.${k}`, v);
      if (typeof v === "string" && v.endsWith(".html")) pages.push(v);
    }
  }

  // web accessible resources (skip globs)
  if (Array.isArray(m.web_accessible_resources)) {
    for (const war of m.web_accessible_resources) {
      if (Array.isArray(war?.resources)) {
        for (const r of war.resources) {
          if (typeof r === "string" && !r.includes("*")) pushStr(all, "web_accessible_resources", r);
        }
      } else if (typeof war === "string" && !war.includes("*")) {
        // MV2-style flat array
        pushStr(all, "web_accessible_resources", war);
      }
    }
  }

  // declarative net request rulesets
  const rulesets = m.declarative_net_request?.rule_resources;
  if (Array.isArray(rulesets)) {
    for (const rs of rulesets) pushStr(all, "declarative_net_request.path", rs?.path);
  }

  return { all, pages: dedupe(pages), scripts: dedupe(scripts) };
}

function collectIcons(out: ManifestFileRef[], source: string, icons: unknown) {
  if (typeof icons === "string") {
    pushStr(out, source, icons);
  } else if (icons && typeof icons === "object") {
    for (const v of Object.values(icons)) pushStr(out, source, v);
  }
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs)];
}
