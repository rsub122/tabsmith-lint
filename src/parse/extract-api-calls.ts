import type {
  ScriptFile,
  ApiCall,
  SensitiveTabRead,
  DynamicApiAccess,
  HostAccessSignal,
} from "../engine/model.js";
import { walk } from "./parse-script.js";

const ROOTS = new Set(["chrome", "browser"]);
const GLOBALS = new Set(["globalThis", "window", "self"]);
const SENSITIVE_PROPS = new Set(["url", "pendingUrl", "title", "favIconUrl"]);
// Match identifiers that name a tab: `tab`, `tabs`, `activeTab`, `currentTab`,
// `tabs[0]` (via recursion) — but NOT `table`, `stable`, `dataTable`, `crontab`.
// Requires `tab`/`tabs` as a trailing word or camelCase segment.
const TAB_NAME = /(?:^|[^a-zA-Z])[Tt]abs?$|[a-z][Tt]abs?$/;
// The chrome.tabs.onUpdated callback's changeInfo carries `url`/`title` only when
// `tabs` is granted, but its param is conventionally named changeInfo/changes
// (not tab-like). A sensitive read off these names is a real Tab read. (Reads of
// non-sensitive props like `info.status` never reach this check.)
const TAB_CONTEXT = new Set(["changeInfo", "changes"]);

interface Resolved {
  root: "chrome" | "browser";
  path: string[];
  dynamic: boolean;
}

type AliasMap = Map<string, { root: "chrome" | "browser"; path: string[] }>;

export interface Extraction {
  apiCalls: ApiCall[];
  sensitiveTabReads: SensitiveTabRead[];
  dynamicApiAccess: DynamicApiAccess[];
  hostAccessSignals: HostAccessSignal[];
}

const MEMBER = new Set(["MemberExpression", "OptionalMemberExpression"]);

function flatten(node: any): { base: any; accesses: any[] } {
  const accesses: any[] = [];
  let cur = node;
  while (cur && MEMBER.has(cur.type)) {
    accesses.unshift({ computed: cur.computed, property: cur.property });
    cur = cur.object;
  }
  return { base: cur, accesses };
}

/** Resolve a member chain to a chrome/browser path, or null if not rooted there. */
function resolveChain(node: any, aliases: AliasMap): Resolved | null {
  const { base, accesses } = flatten(node);
  if (!base || base.type !== "Identifier") return null;

  let root: "chrome" | "browser";
  const path: string[] = [];

  if (ROOTS.has(base.name)) {
    root = base.name as "chrome" | "browser";
  } else if (aliases.has(base.name)) {
    const a = aliases.get(base.name)!;
    root = a.root;
    path.push(...a.path);
  } else if (
    GLOBALS.has(base.name) &&
    accesses[0] &&
    !accesses[0].computed &&
    accesses[0].property?.type === "Identifier" &&
    ROOTS.has(accesses[0].property.name)
  ) {
    root = accesses.shift().property.name;
  } else {
    return null;
  }

  for (const acc of accesses) {
    const p = acc.property;
    if (acc.computed) {
      if (p?.type === "StringLiteral") path.push(p.value);
      else return { root, path, dynamic: true };
    } else if (p?.type === "Identifier") {
      path.push(p.name);
    } else if (p?.type === "StringLiteral") {
      path.push(p.value);
    } else {
      return { root, path, dynamic: true };
    }
  }
  return { root, path, dynamic: false };
}

/** Static-only resolution used while building the alias table (no alias lookup). */
function resolveStatic(node: any): { root: "chrome" | "browser"; path: string[] } | null {
  if (!node) return null;
  if (node.type === "Identifier" && ROOTS.has(node.name)) {
    return { root: node.name, path: [] };
  }
  if (MEMBER.has(node.type)) {
    const r = resolveChain(node, new Map());
    if (r && !r.dynamic) return { root: r.root, path: r.path };
  }
  // Cross-browser polyfill idioms: `chrome || browser`, `browser ?? chrome`,
  // `typeof browser !== 'undefined' ? browser : chrome`. Alias resolves to
  // whichever side is a chrome/browser root.
  if (node.type === "LogicalExpression") {
    return resolveStatic(node.left) ?? resolveStatic(node.right);
  }
  if (node.type === "ConditionalExpression") {
    return resolveStatic(node.consequent) ?? resolveStatic(node.alternate);
  }
  return null;
}

function buildAliases(ast: any): AliasMap {
  const map: AliasMap = new Map();
  walk(ast, (node) => {
    if (node.type !== "VariableDeclarator" || !node.init) return;
    const base = resolveStatic(node.init);
    if (!base) return;
    if (node.id?.type === "Identifier") {
      map.set(node.id.name, { root: base.root, path: base.path });
    } else if (node.id?.type === "ObjectPattern") {
      for (const prop of node.id.properties) {
        if (
          prop.type === "ObjectProperty" &&
          prop.key?.type === "Identifier" &&
          prop.value?.type === "Identifier"
        ) {
          map.set(prop.value.name, { root: base.root, path: [...base.path, prop.key.name] });
        }
      }
    }
  });
  return map;
}

function walkParent(node: any, parent: any, visit: (n: any, parent: any) => void): void {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") visit(node, parent);
  for (const key of Object.keys(node)) {
    if (key === "loc") continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach((c) => walkParent(c, node, visit));
    else if (child && typeof child === "object" && typeof child.type === "string") walkParent(child, node, visit);
  }
}

function isTabish(obj: any): boolean {
  if (!obj) return false;
  if (obj.type === "Identifier") return TAB_NAME.test(obj.name) || TAB_CONTEXT.has(obj.name);
  if (MEMBER.has(obj.type)) return isTabish(obj.object);
  return false;
}

function isAbsoluteUrlArg(arg: any): boolean {
  return arg?.type === "StringLiteral" && /^https?:\/\//i.test(arg.value);
}

export function extractFromScripts(scripts: ScriptFile[]): Extraction {
  const apiCalls: ApiCall[] = [];
  const sensitiveTabReads: SensitiveTabRead[] = [];
  const dynamicApiAccess: DynamicApiAccess[] = [];
  const hostAccessSignals: HostAccessSignal[] = [];

  for (const script of scripts) {
    if (!script.ast || script.parseError) continue;
    const file = script.relPath;
    const aliases = buildAliases(script.ast);

    walkParent(script.ast, null, (node, parent) => {
      if (MEMBER.has(node.type)) {
        const line = node.loc?.start.line;

        // Sensitive tab property read — can appear ANYWHERE in a chain, e.g.
        // `tab.url.startsWith(...)`, so check every member node, not just the top.
        if (!node.computed && node.property?.type === "Identifier" && SENSITIVE_PROPS.has(node.property.name) && isTabish(node.object)) {
          sensitiveTabReads.push({ property: node.property.name as any, file, line });
        }

        // chrome/browser chain resolution only at the top of a chain (the top
        // member carries the whole expression; resolving inner ones double-counts).
        const isTop = !(parent && MEMBER.has(parent.type) && parent.object === node);
        if (isTop) {
          const r = resolveChain(node, aliases);
          if (r) {
            if (r.dynamic) {
              dynamicApiAccess.push({ root: r.root, file, line });
            } else if (r.path.length >= 1) {
              apiCalls.push({ root: r.root, namespace: r.path[0], path: r.path, file, line, column: node.loc?.start.column, confidence: "high" });
            }
          }
        }
        return;
      }

      // Cross-origin fetch
      if (node.type === "CallExpression" && node.callee?.type === "Identifier" && node.callee.name === "fetch") {
        if (isAbsoluteUrlArg(node.arguments?.[0])) {
          hostAccessSignals.push({ kind: "fetch", file, line: node.loc?.start.line });
        }
      }
      // XMLHttpRequest construction
      if (node.type === "NewExpression" && node.callee?.type === "Identifier" && node.callee.name === "XMLHttpRequest") {
        hostAccessSignals.push({ kind: "xhr", file, line: node.loc?.start.line });
      }
    });
  }

  return { apiCalls, sensitiveTabReads, dynamicApiAccess, hostAccessSignals };
}
