#!/usr/bin/env node
// Tier 2 — ACCURACY corpus. Scores the engine against hand-labeled ground truth
// (corpus/labels.json). The headline metric is the PERM001 FALSE-POSITIVE rate:
// flagging a permission as unused when it is actually used destroys trust, and
// staying < 5% on high-confidence findings is the documented gate to promote
// PERM001 from `fix` to `reject` (PRD 5).
//
//   npm run score
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ensureCorpus, loadEngine, REPO_ROOT } from "./lib/corpus.mjs";
import { ensureReleaseCorpus } from "./lib/release-corpus.mjs";

const { analyze } = await loadEngine();
const labelFile = process.argv[2] ?? "corpus/labels.json";
const labels = JSON.parse(readFileSync(join(REPO_ROOT, labelFile), "utf8"));
// Release labels reference the messy real-extension corpus; everything else the samples.
const corpus = labels._corpusKind === "releases" ? ensureReleaseCorpus() : ensureCorpus();

const PERM_IN_TITLE = /Permission "([^"]+)"/;

let perm001Total = 0;
let falsePositives = 0;
let falseNegatives = 0;
let verdictMatches = 0;
const rows = [];

for (const ext of labels.extensions) {
  const r = analyze(join(corpus, ext.path), { version: "score" }).browsers.chrome;

  const toolUnused = new Set(
    r.findings
      .filter((f) => f.ruleId === "PERM001")
      .map((f) => f.title.match(PERM_IN_TITLE)?.[1])
      .filter(Boolean)
  );
  const groundUnused = new Set(ext.unusedPermissions);

  const fps = [...toolUnused].filter((p) => !groundUnused.has(p)); // tool says unused, but it's used
  const fns = [...groundUnused].filter((p) => !toolUnused.has(p)); // truly unused, tool missed
  perm001Total += toolUnused.size;
  falsePositives += fps.length;
  falseNegatives += fns.length;

  const verdictOk = r.verdict === ext.expectVerdict;
  if (verdictOk) verdictMatches++;

  rows.push({
    path: ext.path,
    verdict: `${r.verdict}${verdictOk ? "" : ` (expected ${ext.expectVerdict})`}`,
    fps: fps.join(",") || "-",
    fns: fns.join(",") || "-",
  });
}

console.log(`\nPERM001 accuracy over ${labels.extensions.length} hand-labeled real extensions\n`);
for (const r of rows) {
  const flag = r.fps !== "-" ? " ✗FP" : r.fns !== "-" ? " ·FN" : "";
  console.log(`  ${r.verdict.padEnd(34)} ${r.path}${flag}`);
  if (r.fps !== "-") console.log(`      false positive (said unused, actually used): ${r.fps}`);
  if (r.fns !== "-") console.log(`      false negative (truly unused, not flagged): ${r.fns}`);
}

const fpRate = perm001Total === 0 ? 0 : (falsePositives / perm001Total) * 100;
console.log(`\n  PERM001 findings:        ${perm001Total}`);
console.log(`  False positives:         ${falsePositives}  (${fpRate.toFixed(1)}% of PERM001 findings)`);
console.log(`  False negatives:         ${falseNegatives}`);
console.log(`  Verdict matches:         ${verdictMatches}/${labels.extensions.length}`);
console.log(`\n  Gate to promote PERM001 -> reject: < 5% false positives.`);

if (fpRate > 5) {
  console.error(`\n  FAIL: PERM001 false-positive rate ${fpRate.toFixed(1)}% exceeds 5%.`);
  process.exit(1);
}
console.log(`\n  PASS: false-positive rate within the 5% gate.`);
