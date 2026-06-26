// Fetches real published OSS extensions (built/minified) from pinned GitHub
// release assets into a gitignored cache. These are the "messy" corpus — they
// stress the parser and PERM001 far harder than the clean Google samples.
import { existsSync, readdirSync, statSync, mkdirSync, cpSync, rmSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..");
const CACHE = join(REPO_ROOT, ".corpus-cache", "releases");

function findManifestDir(root, depth = 0) {
  if (existsSync(join(root, "manifest.json"))) return root;
  if (depth > 4) return null;
  for (const e of readdirSync(root, { withFileTypes: true })) {
    if (e.isDirectory() && e.name !== "__MACOSX") {
      const r = findManifestDir(join(root, e.name), depth + 1);
      if (r) return r;
    }
  }
  return null;
}

/** Ensure every pinned release extension is downloaded + unpacked; return the
 *  releases cache root (each extension lives at <root>/<name>/). */
export function ensureReleaseCorpus() {
  const sources = JSON.parse(readFileSync(join(REPO_ROOT, "corpus", "release-sources.json"), "utf8"));
  mkdirSync(CACHE, { recursive: true });
  for (const { name, url } of sources.extensions) {
    const dir = join(CACHE, name);
    if (existsSync(join(dir, "manifest.json"))) continue;
    console.error(`Fetching release extension: ${name}`);
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    const zip = join(CACHE, `_${name}.zip`);
    execFileSync("curl", ["-fsSL", "-o", zip, url]);
    execFileSync("unzip", ["-oq", zip, "-d", dir]);
    rmSync(zip, { force: true });
    if (!existsSync(join(dir, "manifest.json"))) {
      const nested = findManifestDir(dir);
      if (nested && nested !== dir) cpSync(nested, dir, { recursive: true });
    }
  }
  return CACHE;
}
