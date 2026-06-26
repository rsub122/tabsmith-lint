import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, relative, posix, dirname, resolve, sep } from "node:path";
import type { VirtualFile } from "./model.js";
import type { ManifestRefs } from "./manifest-refs.js";
import { stripBom } from "./source-lines.js";

const SCRIPT_EXT = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"];
const HTML_EXT = [".html", ".htm"];
const SCANNABLE = new Set([...SCRIPT_EXT, ...HTML_EXT]);
const EXCLUDE_DIRS = new Set(["node_modules", ".git", "dist", "build", ".cache", "coverage"]);

function ext(path: string): string {
  const i = path.lastIndexOf(".");
  return i < 0 ? "" : path.slice(i).toLowerCase();
}

export function isScript(relPath: string): boolean {
  return SCRIPT_EXT.includes(ext(relPath));
}

export function isHtml(relPath: string): boolean {
  return HTML_EXT.includes(ext(relPath));
}

function toRel(rootDir: string, abs: string): string {
  return relative(rootDir, abs).split(/[\\/]/).join(posix.sep);
}

/** A leading "/" in a manifest reference is root-relative to the EXTENSION, not
 *  the filesystem (e.g. "/images/icon.png" means <ext-root>/images/icon.png).
 *  Normalize to a path relative to rootDir before any filesystem use. */
export function refToRelPath(p: string): string {
  return p.replace(/^[\\/]+/, "");
}

/** True when a manifest reference resolves to a location inside `rootDir`.
 *  Blocks "../secret.js" from escaping the package; allows root-relative "/x". */
export function isWithinRoot(rootDir: string, relPath: string): boolean {
  const root = resolve(rootDir);
  const abs = resolve(rootDir, refToRelPath(relPath));
  return abs === root || abs.startsWith(root + sep);
}

function readVirtual(rootDir: string, relPath: string, discoveredBy: VirtualFile["discoveredBy"]): VirtualFile | null {
  const rel = refToRelPath(relPath);
  if (!isWithinRoot(rootDir, rel)) return null; // never read/parse files outside the package
  const absPath = join(rootDir, rel);
  if (!existsSync(absPath) || !statSync(absPath).isFile()) return null;
  return { relPath: rel, absPath, content: stripBom(readFileSync(absPath, "utf8")), discoveredBy };
}

const SCRIPT_SRC_RE = /<script[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;

function localScriptSrcs(htmlContent: string, htmlRel: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = SCRIPT_SRC_RE.exec(htmlContent)) !== null) {
    const src = m[1];
    if (/^(https?:)?\/\//i.test(src) || src.startsWith("data:")) continue; // remote/inline-data handled by MV3001
    const resolved = posix.normalize(posix.join(dirname(htmlRel) || ".", src)).replace(/^\.\//, "");
    out.push(resolved);
  }
  return out;
}

/**
 * Two-pass discovery: manifest-directed entry points first (tagged "manifest"),
 * then a package-wide fallback scan (tagged "fallback"). Manifest tags win on
 * dedupe. node_modules/.git/build caches and source maps are excluded.
 *
 * Takes pre-collected ManifestRefs so the caller can reuse them (e.g. for
 * model.manifestRefs) without collecting twice.
 */
export function discoverFiles(rootDir: string, refs: ManifestRefs): VirtualFile[] {
  const byRel = new Map<string, VirtualFile>();
  const add = (vf: VirtualFile | null) => {
    if (!vf) return;
    const existing = byRel.get(vf.relPath);
    if (!existing || (existing.discoveredBy === "fallback" && vf.discoveredBy === "manifest")) {
      byRel.set(vf.relPath, vf);
    }
  };

  // --- Pass 1: manifest-directed ---
  for (const s of refs.scripts) add(readVirtual(rootDir, s, "manifest"));
  for (const p of refs.pages) {
    const page = readVirtual(rootDir, p, "manifest");
    add(page);
    if (page && isHtml(p)) {
      for (const src of localScriptSrcs(page.content, p)) add(readVirtual(rootDir, src, "manifest"));
    }
  }

  // --- Pass 2: fallback scan ---
  walk(rootDir, rootDir, (abs) => {
    const rel = toRel(rootDir, abs);
    if (rel === "manifest.json") return;
    if (rel.endsWith(".map")) return;
    if (!SCANNABLE.has(ext(rel))) return;
    add(readVirtual(rootDir, rel, "fallback"));
    if (isHtml(rel)) {
      const page = byRel.get(rel)!;
      for (const src of localScriptSrcs(page.content, rel)) add(readVirtual(rootDir, src, "fallback"));
    }
  });

  return [...byRel.values()];
}

function walk(rootDir: string, dir: string, onFile: (abs: string) => void) {
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const abs = join(dir, e.name);
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(e.name)) continue;
      walk(rootDir, abs, onFile);
    } else if (e.isFile()) {
      onFile(abs);
    }
  }
}
