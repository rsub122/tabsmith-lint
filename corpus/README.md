# Validation corpus

Two tiers of validation against **real** extensions, so the linter is tested on
code it has never seen — not just synthetic fixtures. Everything is fetched on
demand into a gitignored `.corpus-cache/`; nothing is vendored.

Run `npm run build` first (the scripts use the compiled engine in `dist/`).

## Two corpora

**Clean samples** — [GoogleChrome/chrome-extensions-samples](https://github.com/GoogleChrome/chrome-extensions-samples)
(Apache-2.0), ~100 small, readable MV3 extensions. Labels in `labels.json` (22 hand-labeled).

**Messy releases** — real published, **built/minified** OSS extensions (uBlock Origin,
Dark Reader, Stylus, SponsorBlock, Return YouTube Dislike, FastForward, Violentmonkey),
fetched from **pinned GitHub release assets** (`release-sources.json`). These stress the
parser and PERM001 far harder. Labels in `labels-releases.json` (6 hand-labeled for
accuracy; all 7 run for robustness).

## Tier 1 — robustness (`npm run validate` / `npm run validate:releases`)

Runs the engine over every extension and reports crash count, verdict distribution,
and finding frequency. **Gate: zero crashes** on real input. Point it at any tree of
unpacked extensions with `npm run validate -- <dir>`.

## Tier 2 — accuracy (`npm run score` / `npm run score:releases`)

Scores the engine against hand-labeled ground truth. The label for a permission is
**"actually used by the implementation"** (PRD §2.6/§5) — found by reading the code —
not "the extension passed review". Minified code preserves `chrome.*` member names, so
namespace usage stays grep-able even in bundles.

The headline metric is the **PERM001 false-positive rate**: flagging a permission as
unused when it is actually used destroys trust. Staying **under 5%** on high-confidence
findings is the documented gate to promote PERM001 from `fix` to `reject`. Across **28
hand-labeled extensions** (22 samples + 6 releases): **0% false positives, 0 false
negatives, all verdicts matched** — both independently audited by a second agent.

## False positives found and fixed by this corpus

Six, each now with a regression test — plus a prototype-safety crash:

1. Root-relative `/images/icon.png` treated as filesystem-absolute (FUNC001).
2. Sensitive Tab reads mid-chain (`tab.url.startsWith(...)`) missed by top-of-chain-only extraction.
3. `declarativeNetRequest` used declaratively via manifest rulesets (no JS call).
4. `changes.url` read inside `chrome.tabs.onUpdated` (the `changeInfo` param isn't named tab-like).
5. `declarativeNetRequestWithHostAccess` not recognized as granting the DNR namespace (PERM002).
6. Cross-browser polyfill alias `const api = browser || chrome` / `cond ? browser : chrome` not resolved.
7. (crash) A namespace named like an `Object.prototype` key (`chrome.constructor`) hit the prototype on lookup — fixed with null-prototype maps.

## Known limitation (documented, not hidden)

`violentmonkey` is in the robustness set (parses without crashing) but **excluded from
accuracy**: it accesses the API via `T.contextMenus`, where `T` is a webpack-minified
`webextension-polyfill` module import. Static analysis can't resolve the module, so
PERM001 false-positives on `contextMenus`. Deep bundler-module-wrapped API access is a
known limitation — precisely why PERM001 ships at `fix`, not `reject`.

## Demo (`npm run demo`)

Prints the human report for a few recognizable real extensions. `npm run demo -- <dir>`
targets any unpacked extension. For a Chrome Web Store `.crx` (a ZIP with a header):
`unzip -o ext.crx -d ./ext` then point the demo or CLI at `./ext`.
