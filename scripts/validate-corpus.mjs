#!/usr/bin/env node
// Tier 1 — ROBUSTNESS corpus. Runs the engine over a large set of real MV3
// extensions and reports: crash count (must be 0), verdict distribution, and
// finding frequency. A standing regression gate against real-world input.
//
//   npm run validate            # uses the cached Google sample corpus
//   npm run validate -- <dir>   # any directory tree of unpacked extensions
import { ensureCorpus, findMv3Dirs, loadEngine, REPO_ROOT } from "./lib/corpus.mjs";
import { ensureReleaseCorpus } from "./lib/release-corpus.mjs";
import { relative, join } from "node:path";
import { existsSync, readdirSync } from "node:fs";

const { analyze } = await loadEngine();
const arg = process.argv[2];
let root, dirs;
if (arg === "--releases") {
  // Robustness on the messy corpus includes MV2 bundles (parsing stress), so take
  // every extension dir, not just MV3 ones.
  root = ensureReleaseCorpus();
  dirs = readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(root, e.name, "manifest.json")))
    .map((e) => join(root, e.name));
} else {
  root = arg ?? ensureCorpus();
  dirs = findMv3Dirs(root);
}

const verdicts = {};
const rules = {};
const crashes = [];
for (const dir of dirs) {
  try {
    const r = analyze(dir, { version: "validate" }).browsers.chrome;
    verdicts[r.verdict] = (verdicts[r.verdict] || 0) + 1;
    for (const f of r.findings) rules[f.ruleId] = (rules[f.ruleId] || 0) + 1;
  } catch (e) {
    crashes.push({ dir: relative(REPO_ROOT, dir), error: e.message });
  }
}

console.log(`\nRan on ${dirs.length} real extensions.`);
console.log(`Crashes: ${crashes.length}`);
for (const c of crashes) console.log(`  ✗ ${c.dir}: ${c.error}`);
console.log("\nVerdicts:");
for (const [k, v] of Object.entries(verdicts).sort((a, b) => b[1] - a[1])) console.log(`  ${k}: ${v}`);
console.log("\nFinding frequency:");
for (const [k, v] of Object.entries(rules).sort((a, b) => b[1] - a[1])) console.log(`  ${k}: ${v}`);

// The gate: a linter that crashes on real input is broken. Verdicts are informational.
if (crashes.length > 0) {
  console.error(`\nFAIL: ${crashes.length} crash(es) on real extensions.`);
  process.exit(1);
}
console.log("\nPASS: 0 crashes on real input.");
