// Shared helpers for the validation scripts. Fetches a corpus of REAL Manifest V3
// extensions (Google's official samples, Apache-2.0) on demand into a gitignored
// cache — no vendoring — and walks it for analyzable extension directories.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..");
export const VERSION = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")).version;
const CACHE = join(REPO_ROOT, ".corpus-cache", "chrome-extensions-samples");
const SOURCE = "https://github.com/GoogleChrome/chrome-extensions-samples.git";

/** Ensure the sample corpus is present (shallow-cloned once), return its path. */
export function ensureCorpus() {
  if (!existsSync(CACHE)) {
    console.error("Fetching real-extension corpus (Google chrome-extensions-samples, shallow clone)...");
    execFileSync("git", ["clone", "--depth", "1", SOURCE, CACHE], { stdio: "inherit" });
  }
  return CACHE;
}

/** All directories under `root` that contain an MV3 manifest.json. */
export function findMv3Dirs(root) {
  const out = [];
  (function walk(d) {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === ".git" || e.name === "node_modules") continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === "manifest.json") {
        try {
          if (JSON.parse(readFileSync(p, "utf8")).manifest_version === 3) out.push(d);
        } catch {
          /* ignore unparseable manifests during discovery */
        }
      }
    }
  })(root);
  return out.sort();
}

/** Load the built engine from dist/, with a clear error if it isn't built yet. */
export async function loadEngine() {
  const analyzePath = join(REPO_ROOT, "dist", "engine", "analyze.js");
  if (!existsSync(analyzePath)) {
    console.error("dist/ not found — run `npm run build` first.");
    process.exit(2);
  }
  const { analyze } = await import(analyzePath);
  const { renderHuman } = await import(join(REPO_ROOT, "dist", "reporters", "human.js"));
  return { analyze, renderHuman };
}
