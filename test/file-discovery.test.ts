import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverFiles } from "../src/engine/file-discovery.js";
import { collectManifestRefs } from "../src/engine/manifest-refs.js";

function tree(): string {
  const dir = mkdtempSync(join(tmpdir(), "tsl-disc-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({
    manifest_version: 3,
    background: { service_worker: "background.js" },
    content_scripts: [{ matches: ["<all_urls>"], js: ["content.js"] }],
    action: { default_popup: "popup.html" },
  }));
  writeFileSync(join(dir, "background.js"), "// bg");
  writeFileSync(join(dir, "content.js"), "// cs");
  writeFileSync(join(dir, "helper.js"), "// loose, not referenced");
  writeFileSync(join(dir, "popup.html"), '<script src="popup.js"></script>');
  writeFileSync(join(dir, "popup.js"), "// popup");
  writeFileSync(join(dir, "bundle.js.map"), "{}");
  mkdirSync(join(dir, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(dir, "node_modules", "dep", "index.js"), "// vendor");
  return dir;
}

describe("U3: two-pass file discovery", () => {
  it("finds manifest entry points, loose fallback files, html script-srcs; excludes node_modules + maps", () => {
    const dir = tree();
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    const files = discoverFiles(dir, collectManifestRefs(manifest));
    const rels = files.map((f) => f.relPath).sort();

    expect(rels).toContain("background.js");
    expect(rels).toContain("content.js");
    expect(rels).toContain("popup.html");
    expect(rels).toContain("popup.js"); // discovered via <script src> in popup.html
    expect(rels).toContain("helper.js"); // fallback scan

    // exclusions
    expect(rels.some((r) => r.includes("node_modules"))).toBe(false);
    expect(rels.some((r) => r.endsWith(".map"))).toBe(false);

    // discovery tags: background.js via manifest, helper.js via fallback
    expect(files.find((f) => f.relPath === "background.js")!.discoveredBy).toBe("manifest");
    expect(files.find((f) => f.relPath === "helper.js")!.discoveredBy).toBe("fallback");

    rmSync(dir, { recursive: true, force: true });
  });
});
