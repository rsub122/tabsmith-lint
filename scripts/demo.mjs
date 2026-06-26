#!/usr/bin/env node
// Shareable demo. Runs the linter against a few real, recognizable extensions
// from the corpus and prints the human report — proof the tool catches genuine
// rejection risks in code it has never seen.
//
//   npm run demo                 # curated real extensions from the corpus
//   npm run demo -- <ext-dir>    # any unpacked extension directory
//
// For an actual Chrome Web Store .crx: it is a ZIP with a header, so
//   unzip -o some-extension.crx -d ./some-extension   # then point demo/CLI at it
import { join } from "node:path";
import { ensureCorpus, loadEngine, VERSION } from "./lib/corpus.mjs";

const { analyze, renderHuman } = await loadEngine();

const CURATED = [
  "functional-samples/tutorial.mole-game/mole", // over-declares management + tabs
  "api-samples/cookies/cookie-clearer", // requests <all_urls>
  "functional-samples/sample.catifier", // declarative DNR + broad host
];

const targets = process.argv[2]
  ? [process.argv[2]]
  : CURATED.map((p) => join(ensureCorpus(), p));

for (const dir of targets) {
  console.log("\n" + "=".repeat(72));
  const report = analyze(dir, { version: VERSION });
  console.log(renderHuman(report));
}
console.log("\n" + "=".repeat(72));
console.log("Every finding above was produced from source the linter had never seen.");
