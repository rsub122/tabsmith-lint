# tabsmith-lint

<p>
<a href="https://www.npmjs.com/package/tabsmith-lint"><img alt="npm version" height="28" src="https://img.shields.io/npm/v/tabsmith-lint?logo=npm&color=cb3837"></a>
<a href="https://www.npmjs.com/package/tabsmith-lint"><img alt="npm downloads" height="28" src="https://img.shields.io/npm/dt/tabsmith-lint?logo=npm&color=cb3837"></a>
<a href="https://github.com/rsub122/tabsmith-lint/actions/workflows/ci.yml"><img alt="CI" height="28" src="https://img.shields.io/github/actions/workflow/status/rsub122/tabsmith-lint/ci.yml?branch=main&logo=github&label=CI"></a>
<a href="https://github.com/rsub122/tabsmith-lint/blob/main/package.json"><img alt="node" height="28" src="https://img.shields.io/node/v/tabsmith-lint?logo=node.js"></a>
<a href="LICENSE"><img alt="license" height="28" src="https://img.shields.io/npm/l/tabsmith-lint?color=blue"></a>
<a href="https://packagephobia.com/result?p=tabsmith-lint"><img alt="install size" height="28" src="https://packagephobia.com/badge?p=tabsmith-lint"></a>
<a href="https://github.com/rsub122/tabsmith-lint/stargazers"><img alt="GitHub stars" height="28" src="https://img.shields.io/github/stars/rsub122/tabsmith-lint?style=flat&logo=github"></a>
</p>

A pre-submission compliance linter for browser extensions. It analyzes an unpacked
Manifest V3 Chrome extension (an unpacked directory, or the `.zip`/`.crx` you upload)
and reports likely Chrome Web Store rejection risks **before** you submit — unused/excessive permissions, missing permissions, MV3
violations, and broken file references — with a clear verdict and actionable fixes.

**Catch the "Purple Potassium" permission rejection before you submit.** The most
common Chrome Web Store rejection is excessive/unused permissions — declaring `tabs`,
`bookmarks`, `cookies`, or `<all_urls>` your code never actually uses. tabsmith-lint
statically checks your manifest against your code and maps findings to the violations
Chrome reviewers flag:

| Violation ID | What it means | tabsmith rules |
|---|---|---|
| Purple Potassium | Excessive / unused permissions | PERM001, PERM003, PERM004, PERM005 |
| Blue Argon | Remotely hosted code / latent remote loaders / string execution / forbidden CSP | MV3001, MV3005, MV3002, MV3004 |
| Yellow Magnesium | Functionality / broken packaging | FUNC001, FUNC002 |
| Red Titanium | Obfuscated code (minification is fine) | OBF001 |
| Harmful / unexpected behavior | DNR rules that strip sites' security headers | SEC001 |
| Upload / package hygiene | Secrets, `.git`, `node_modules` etc. in the zip; 2 GB limit; leftover `"key"` | PKG001, PKG003, PKG002 |

```bash
npx tabsmith-lint ./my-extension
npx tabsmith-lint ./my-extension --format json
npx tabsmith-lint ./my-extension --min-severity reject
npx tabsmith-lint ./my-extension.zip       # lint exactly what you upload (.zip or .crx)
```

Exit codes: `0` pass · `1` needs fixes · `2` high rejection risk · `3` tool error.

No install needed — `npx` runs the latest published version. Or install it: `npm i -g tabsmith-lint`.

## Develop

```bash
npm install
npm test      # vitest: unit + e2e (one fixture per rule)
npm run build # tsc → dist/
node dist/cli.js ./my-extension
```

## Validate against real extensions

Beyond the unit/e2e fixtures, the linter is validated on **real** extensions —
both Google's clean MV3 samples and real published, **built/minified** OSS
extensions (uBlock Origin, Dark Reader, Stylus, ...). All fetched on demand — see
`corpus/`:

```bash
npm run build               # required first — the scripts use dist/
npm run validate            # robustness: ~100 clean extensions, gate on 0 crashes
npm run score               # accuracy: PERM001 false-positive rate vs ground truth
npm run validate:releases   # robustness on real minified extensions
npm run score:releases      # accuracy on the messy corpus
npm run demo                # print reports for recognizable real extensions
```

`npm run score` gates promoting PERM001 to `reject`: under 5% false positives.
Across **28 hand-labeled extensions (22 samples + 6 minified releases): 0% false
positives, 0 false negatives, all verdicts matched** — independently audited.
Building this corpus caught and fixed **six** real false positives (plus a
prototype-safety crash) the synthetic fixtures missed — see `corpus/README.md`. CI
runs the suite and all validation gates on every push (`.github/workflows/ci.yml`).

## PERM001 accuracy gate

PERM001 (declared-but-unused permission) is the flagship rule, and its
false-positive rate is make-or-break — a wrong "remove this permission" suggestion
destroys trust. In v0.1 it ships at **`fix` severity, never `reject`** (the single
constant `PERM001_SEVERITY` in `src/rules/permissions.ts`). Promoting it to `reject`
is gated on validating under 5% false positives against a hand-labeled corpus of
20–30 real extensions, where the label is "permission actually used by
implementation" — not "extension passed review". That corpus is deferred; until it
exists, leave the severity at `fix`.

## Status

Chrome-only, directory or `.zip`/`.crx` input, 17 rules (PERM001-005, MV3001-005, FUNC001-002,
SEC001, OBF001, PKG001-003).

MV3001 (remotely hosted code, `reject`) covers HTML `<script src="https://…">`, remote
`import`/`import()`, remote `importScripts()`, a remote `src` set on a
`document.createElement("script")` element (`.src =`, `setAttribute("src", …)`,
`Object.assign(…, { src })`), and remote entries in
`chrome.scripting.executeScript({ files })` / `registerContentScripts([{ js }])` /
`updateContentScripts`. Fetching remote JSON/data with `fetch`/XHR is not
remotely hosted code and is never flagged; neither are `img`/`iframe` sources or
computed URLs.

MV3005 (latent remote-code loader) covers what MV3001 deliberately leaves out: bundled
code that *could* load a remote script. A `<script>` element (or `importScripts`) given
a computed `src` is `fix` when the URL is built on a remote prefix
(`"https://cdn/" + v`, including a prefix held in a variable bound only to that string,
`var base = "https://cdn/"; s.src = base + "x.js"`) or the same file also contains a
remote `.js`/`.mjs` URL literal;
the finding names the URL and, when a banner or `vendor/` path identifies it, the
bundled package. Other remote `.js` URL literals in shipped code are `info` (they never
change the verdict). Only `.js`/`.mjs` URLs count, so remote JSON/data endpoints are
never flagged.

SEC001 (DNR security-header stripping) reads static `declarative_net_request` rulesets
and literal `updateDynamicRules`/`updateSessionRules` rules, and flags `modifyHeaders`
that `remove`/`set` `Content-Security-Policy`(-Report-Only), `X-Frame-Options`,
`Cross-Origin-Opener/Embedder/Resource-Policy` or `Strict-Transport-Security`. It is
`fix` when the condition isn't scoped to specific domains and the extension has broad
host access, otherwise `info`.

OBF001 (obfuscated code, Red Titanium, `fix`) looks for fingerprints that minifiers
never produce: `_0x`-style hexadecimal identifiers in quantity, javascript-obfuscator's
string-array rotator and hex-index lookups, Dean Edwards' `eval(function(p,a,c,k,e,d)…)`
packer, `eval`/`Function` run on a decoded string (`eval(atob(…))`,
`new Function(String.fromCharCode(…))`), and plain-text strings spelled with `\x`/`\u`
escapes. One finding per file, naming the bundled package from its license banner,
`node_modules/` or `vendor/` path, or the bundler's module comment. Measured precision:
0 findings on 43 popular npm browser packages (lodash, react-dom, vue, chart.js, three,
pdf.js, @babel/standalone, crypto libraries, ... — 12,041 script files), the 7 minified
release extensions and the Google samples; 37 of 38 obfuscated samples flagged.

**Archive input (`.zip`/`.crx`).** Pass the zip you upload to the Chrome Web Store (or a
CRX2/CRX3 file: header, then zip) and every rule runs on exactly what ships. The reader
uses only Node built-ins (no new dependency); it never writes outside a private temp
directory, never follows symlinks, refuses ZIP64/encrypted entries, and caps extracted
code at 512 MiB. Inside an archive, `build/`/`dist/` folders are scanned like any other
code because they ship. If `manifest.json` sits inside a folder in the zip (the classic
"zipped the folder, not its contents" mistake) you get exit 3 with that explanation.
The package rules:

| Rule | Severity | What it flags |
|---|---|---|
| PKG001 | `fix` | `.env*` files, private keys (`*.pem`), `.git`/`.svn`/`.hg`, `node_modules/`, or entries with unsafe (`../`, absolute) paths inside the archive. `node_modules` files the manifest actually loads drop it to `info` |
| PKG001 | `info` | source maps (allowed, but they publish your source), test folders/`*.test.js`/`*.spec.js`, OS junk (`.DS_Store`, `__MACOSX/`, `Thumbs.db`) |
| PKG002 | `info` | `"key"` in manifest.json (a development-only stable-ID field), for directories too |
| PKG003 | `reject` / `info` | archive over the 2 GB package limit / within 10% of it |

PKG001 and PKG003 run on archive input only: a source directory normally contains
`node_modules`, `.git` and tests that never get zipped. Measured: the 295 Google sample
directories with a valid manifest (zipped), 6 real release zips and 2 Chrome Web Store
CRX downloads all gave the same verdict and the same non-PKG findings as the unpacked
directory (a 7th release zip, uBlock's, nests `manifest.json` in a folder and is
correctly refused). The only PKG001 hits were real test folders (`info`).

Firefox/Edge, SARIF, and a GitHub Action are on the roadmap.

Two rules are intentionally conservative in v0.1 (trust is the product): **PERM001**
(unused permission) and **MV3002** (string execution: `eval`/`new Function`) both ship
at `fix` severity, not `reject` — a static linter can't always tell a real problem from
a sandboxed or unreachable one, so they surface for you to verify rather than condemn.
Each is gated behind a single severity constant for later promotion.

## License

MIT — see [LICENSE](LICENSE).
