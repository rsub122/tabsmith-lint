import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { analyze } from "../src/engine/analyze.js";
import type { BrowserReport } from "../src/engine/model.js";

/** Build a throwaway extension dir from a {relPath: content} map and analyze it.
 *  manifest must be supplied as the "manifest.json" key (object or string). */
export function analyzeExt(files: Record<string, string | object>): BrowserReport {
  const dir = mkdtempSync(join(tmpdir(), "tsl-ext-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, typeof content === "string" ? content : JSON.stringify(content));
    }
    return analyze(dir, { version: "0.1.0-test" }).browsers.chrome;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
