import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ManifestJson } from "./model.js";
import { stripBom } from "./source-lines.js";

export interface ManifestLoad {
  manifest: ManifestJson;
  raw: string;
}

export class ManifestError extends Error {}

/**
 * Load and minimally validate manifest.json from an extension directory.
 * Throws ManifestError (→ CLI exit 3) on a missing dir, missing/unreadable
 * manifest, malformed JSON, or absent manifest_version. We deliberately do NOT
 * deep-validate the schema here — rules handle semantics.
 */
export function loadManifest(rootDir: string): ManifestLoad {
  if (!existsSync(rootDir) || !statSync(rootDir).isDirectory()) {
    throw new ManifestError(`Not a directory: ${rootDir}`);
  }
  const manifestPath = join(rootDir, "manifest.json");
  if (!existsSync(manifestPath)) {
    throw new ManifestError(`No manifest.json found in ${rootDir}`);
  }

  let raw: string;
  try {
    raw = stripBom(readFileSync(manifestPath, "utf8"));
  } catch (e) {
    throw new ManifestError(`Could not read manifest.json: ${(e as Error).message}`);
  }

  let manifest: ManifestJson;
  try {
    manifest = JSON.parse(raw);
  } catch (e) {
    throw new ManifestError(`manifest.json is not valid JSON: ${(e as Error).message}`);
  }

  if (typeof manifest !== "object" || manifest === null) {
    throw new ManifestError("manifest.json must be a JSON object");
  }
  if (typeof manifest.manifest_version !== "number") {
    throw new ManifestError("manifest.json is missing a numeric manifest_version");
  }

  return { manifest, raw };
}
