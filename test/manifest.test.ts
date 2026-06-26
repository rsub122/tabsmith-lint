import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadManifest, ManifestError } from "../src/engine/manifest.js";
import { fixtureDir } from "./helpers.js";

function tmpExt(manifestContent: string): string {
  const dir = mkdtempSync(join(tmpdir(), "tsl-"));
  writeFileSync(join(dir, "manifest.json"), manifestContent);
  return dir;
}

describe("U2: manifest loading", () => {
  it("valid MV3 manifest → parsed object with manifest_version 3", () => {
    const { manifest } = loadManifest(fixtureDir("pass-basic-mv3"));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBe("Pass Basic");
  });

  it("missing manifest.json → ManifestError", () => {
    const dir = mkdtempSync(join(tmpdir(), "tsl-empty-"));
    expect(() => loadManifest(dir)).toThrow(ManifestError);
    rmSync(dir, { recursive: true, force: true });
  });

  it("malformed JSON → ManifestError, no crash", () => {
    const dir = tmpExt("{ not valid json ");
    expect(() => loadManifest(dir)).toThrow(ManifestError);
    rmSync(dir, { recursive: true, force: true });
  });

  it("missing manifest_version → ManifestError", () => {
    const dir = tmpExt('{ "name": "x" }');
    expect(() => loadManifest(dir)).toThrow(/manifest_version/);
    rmSync(dir, { recursive: true, force: true });
  });
});
