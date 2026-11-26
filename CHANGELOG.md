# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-11-26

### Added
- **`.zip` / `.crx` input: lint exactly what you upload.**
  `npx tabsmith-lint my-extension.zip` (or a CRX2/CRX3 file: header, then zip). Every
  existing rule runs on the archive's contents. The reader uses only Node built-ins (no
  new dependency) and reads the zip central directory through a file descriptor. It
  supports stored and deflate entries, never writes outside a private temp directory
  (it skips `../` and absolute entry names), never creates or follows symlinks, refuses
  ZIP64, encrypted and multi-disk archives with a clear error, refuses entries that
  inflate past their declared size, and caps extracted code/JSON at 512 MiB. Images and
  other binaries are not extracted (empty placeholders keep FUNC001/FUNC002 accurate).
  The temp directory is removed after every run, including runs that fail.
  Inside an archive, `build/` and `dist/` folders are scanned like any other code
  because they ship. `node_modules/` and `.git/` are still not code-scanned; PKG001
  reports them instead.
- If `manifest.json` is not at the zip root but inside a folder (zipping the folder
  instead of its contents), the run exits 3 and says so, naming the nested path. The
  Chrome Web Store requires the manifest at the root.
- **New rule PKG001: files that should not ship** (archive input only):
  - `fix`: `.env*` files, private keys (`*.pem`), `.git`/`.svn`/`.hg` metadata,
    `node_modules/`, entries with unsafe paths. A `node_modules` file that the
    manifest (or a manifest page's `<script>`) actually loads drops that finding to
    `info` and is named, so the advice never breaks the extension.
  - `info`: source maps (allowed, but they publish your source), test folders and
    `*.test.*`/`*.spec.*` files, OS junk (`.DS_Store`, `__MACOSX/`, `Thumbs.db`).
  One finding per category, listing up to 5 paths and a count.
- **New rule PKG002: `"key"` in manifest.json** (`info`, any input). It is a
  development-time stable-ID field; the store assigns the published item its own ID.
- **New rule PKG003: 2 GB package limit** (archive input): `reject` above 2 GiB
  ("Zip files larger than 2GB will be rejected"), `info` within 10% of it.
- Human output shows "N files in package" for archive input; JSON adds
  `stats.packageFiles` and reports the archive path as `inputPath`.
- `--help`, the usage line and the README (rule table, archive section) cover archive
  input and the PKG rules.
- 46 new tests (261 → 307), including a test-only zip writer (stored/deflate, CRX2/3,
  unix modes) and zip-slip, symlink, zip-bomb, bad-CRX and temp-cleanup cases.

### Precision
- Archive vs. directory parity: the 295 Google sample directories with a valid
  manifest (zipped with Python's zipfile), 6 real release zips (Dark Reader,
  SponsorBlock, Stylus, Return YouTube Dislike, FastForward, Violentmonkey) and 2
  CRX3 files downloaded from the Chrome Web Store (uBlock Origin Lite, 933 files;
  Dark Reader) all gave the same verdict and the same non-PKG findings as the
  unpacked directory. uBlock's release zip nests `manifest.json` in a folder and is
  correctly refused. The 9 sample manifests that are invalid JSON fail the same way in
  both modes.
- PKG001 on that corpus: 5 findings, all `info`, all real test folders. A first draft
  also treated `spec/` folders as tests. That flagged CodeMirror's runtime RPM `spec`
  language mode, so `spec/` was dropped (only `*.spec.*` file names count).
- PKG002: 17 findings (16 samples + Stylus's `-id` build), every one a literal
  top-level `"key"`.
- Existing gates unchanged: 0 crashes on the samples and releases, PERM001 0% false
  positives, 28/28 verdicts.

## [0.5.0] - 2026-11-23

### Added
- **New rule OBF001: obfuscated code** (Chrome Web Store "Red Titanium", `fix`).
  Minification is allowed; obfuscation is not. OBF001 only fires on fingerprints that
  minifiers never produce:
  - `_0x`-style hexadecimal identifiers in quantity (10 or more distinct names);
  - javascript-obfuscator's string-array rotator (`arr.push(arr.shift())` in a
    function that also runs the `parseInt` checksum or a `while (--n)` countdown);
  - string-array lookups: one function called 25+ times with small hex indices
    (`_0x1a2b(0x1f4)`, 15+ distinct values). Colour and hash constants don't count;
  - Dean Edwards' packer, `eval(function(p,a,c,k,e,d){…}(…))`;
  - `eval` / `Function` / `new Function` run on a decoded string (`atob`, `unescape`,
    `decodeURIComponent`, `String.fromCharCode`);
  - 20+ plain-ASCII strings spelled entirely with `\x`/`\u` escapes.
  One finding per file, at the first signal's line. It names the bundled package from
  the license banner, a `node_modules/` or `vendor/` path, or the nearest bundler
  module comment (esbuild `// node_modules/x/…`, webpack `./node_modules/x/…`). If
  the nearest module comment is first-party code, no package is blamed.
- **MV3005 now follows a remote prefix held in a variable**:
  `var base = "https://cdn/"; s.src = base + "x.js"` (also template literals,
  `setAttribute("src")`, `importScripts(base + …)`, and a variable that holds a full
  remote URL) → `fix`. This only applies when every binding of that name in the file
  is that one string literal; parameters, reassignments, `+=`, conflicting literals,
  local or `getURL` prefixes are not followed. A URL that is already reported this way
  is not repeated as an `info` finding.
- Fixture `obfuscated-vendor`, and 66 new tests (195 → 261).

### Precision
- OBF001: 0 findings on 43 popular npm browser packages bundled into test extensions
  (12,041 script files: lodash, react-dom, vue, chart.js, three, pdf.js,
  @babel/standalone, firebase, crypto-js, node-forge, openpgp, libsodium, sql.js,
  highlight.js, katex, moment, d3, jszip, core-js and more), 0 on the 7 minified
  release extensions (457 files), and 0 on the Google samples. On 38 obfuscated
  samples (javascript-obfuscator 5.10.1 in 11 configurations over 3 inputs, plus
  packer, `eval(atob)`, `new Function(String.fromCharCode)`, bundle and vendor-path
  cases) it flagged 37. The miss is a 30-line script obfuscated with mangled names and
  without rotation.
- MV3005 change: corpus findings are unchanged (full cache scan identical). On the 13
  packages from v0.4.0 nothing changed. Of the 30 new packages, one finding changed:
  three.js `examples/jsm/physics/AmmoPhysics.js` (`script.src = AMMO_PATH`, a real
  jsDelivr loader) was already `fix`, and its message now names the variable.

### Changed
- `--help` and the README list OBF001; the README rule count is now 14 and the
  violation table has a Red Titanium row.

## [0.4.0] - 2026-11-19

### Added
- **MV3001 now covers `chrome.scripting` with remote files** (Blue Argon, `reject`):
  a literal `https://`, `http://` or protocol-relative entry in
  `scripting.executeScript({ files })`, `registerContentScripts([{ js }])` or
  `updateContentScripts([{ js }])` (`chrome.*` or `browser.*`). Local paths, computed
  entries, `func` injections and CSS files are not flagged.
- **New rule MV3005: latent remote-code loader** (Blue Argon). Bundled code that
  *could* load a remote script, which reviewers judge even if it never runs:
  - `fix`: a `document.createElement("script")` element (or `importScripts`) given a
    computed `src` that is built on a remote prefix (`"https://cdn/" + v`,
    `` `https://cdn/${v}.js` ``), or whose file also contains a remote `.js`/`.mjs`
    URL literal. One finding per file, listing the other loader lines; it names the
    URL and the bundled package when a banner or `vendor/` path identifies it.
  - `info`: remote `.js`/`.mjs` URL literals in shipped code that no other finding
    explains (never changes the verdict).
  Only `.js`/`.mjs` URLs count, so remote JSON/data fetches are never flagged;
  `chrome.runtime.getURL(...)` sources and GitHub/GitLab source-page links are ignored.
- **New rule SEC001: declarativeNetRequest rules that strip security headers.**
  `modifyHeaders` rules (static rulesets and literal `updateDynamicRules` /
  `updateSessionRules` rules) that `remove` or `set` `Content-Security-Policy`
  (and `-Report-Only`), `X-Frame-Options`, `Cross-Origin-Opener/Embedder/Resource-Policy`
  or `Strict-Transport-Security`. `fix` when the condition is not scoped to specific
  domains and the extension has broad host access; `info` when scoped or host access
  is narrow. `append` and request headers are not judged.
- Fixtures `remote-scripting-files`, `latent-loader` and `dnr-strip-headers`, and
  67 new tests (128 → 195).

### Precision
- On the corpus (106 Chrome samples + 7 built/minified releases, plus the full
  312-extension cache including `_archive`), findings are unchanged: 0 MV3005 and
  0 SEC001 findings, MV3001 still 13, and the PERM001 scores are the same.
- On 13 popular npm browser packages bundled into a test extension (jQuery, lodash,
  axios, React DOM, Vue, Chart.js, DOMPurify, Sentry, PostHog, rrweb,
  webextension-polyfill, Mixpanel, Amplitude), only the Mixpanel and Amplitude CDN
  snippet loaders are reported, and both really do load a remote script.

### Changed
- `--help` and the README list the new detections; the README rule count is now 13.

## [0.3.0] - 2026-11-16

### Added
- **MV3001 now detects remote code injected from JavaScript** (Blue Argon, `reject`):
  a `<script>` element created with `document.createElement("script")` whose `src`
  is set to a literal `https://`, `http://` or protocol-relative URL via `.src =`,
  `["src"] =`, `setAttribute("src", …)` or `Object.assign(…, { src })`, including
  the chained `document.createElement("script").src = …` form. Remote `fetch`/XHR of
  JSON or data, `img`/`iframe`/`link` sources, non-script elements, local paths,
  `chrome.runtime.getURL(...)` and computed URLs are never flagged, and a variable
  name that is ever bound to anything else in the file is not tracked. The fix hint
  notes that fetching remote data is allowed.
- Fixture `remote-injected-script` and 29 MV3001 tests (7 positive, 21 negative, 1 e2e),
  plus tests for the new `--help` text and the PERM005 hint (97 → 128 tests).

### Changed
- PERM005's fix hint now suggests moving broad access to `optional_host_permissions`
  and requesting it at runtime with `chrome.permissions.request()`.
- `--help` no longer says "only chrome in v0.1"; the `--browser` error message is
  version-neutral too.
- README: corrected the rule count (11 rules, not 12) and documented MV3001's scope.
- `package.json` `bin` path is now `dist/cli.js` (npm normalized `./dist/cli.js` at
  publish time).

### Security
- Resolved all 7 `npm audit` findings (1 moderate, 4 high, 2 critical; all in
  dev/test tooling, none in the published runtime): `npm audit fix` plus vitest
  3.2.6 → 4.1.12 (which drops `tinypool` and pulls in patched `vite`, `postcss`,
  `nanoid` and `source-map-js`). `npm audit` now reports 0 vulnerabilities.

### Validation
- 0 MV3001 findings and 0 crashes, unchanged, on the 106-extension sample corpus and the 7 real
  minified release extensions; PERM001 is still at 0% false positives with all 28 labeled
  verdicts matched. Several release extensions (uBlock Origin, Stylus, SponsorBlock,
  FastForward, Return YouTube Dislike) create local `<script>` elements and are correctly
  not flagged. Across the whole fetched sample tree, including the archived MV2/Apps
  samples, the new check adds 2 findings, both real remote loaders (`ga.js`, Google API `client.js`).

## [0.2.0] - 2026-11-12

### Added
- **MV3001 now detects remote `importScripts()`**: `importScripts("https://…")`,
  `importScripts("//…")`, and the `self.` / `globalThis.` forms (including
  expression-free template literals) are reported as remotely hosted code
  (Blue Argon, `reject`). Local paths and computed URLs are never flagged.
- **New rule MV3004: forbidden extension-page CSP** (Blue Argon, `reject`). Flags a
  string-form `content_security_policy` in a Manifest V3 manifest, and
  `content_security_policy.extension_pages` whose `script-src`, `object-src` or
  `worker-src` contain `'unsafe-eval'`, `'unsafe-inline'`, or remote/wildcard/scheme
  sources. `'self'`, `'none'`, `'wasm-unsafe-eval'` and localhost sources are
  allowed, the `sandbox` policy is never inspected, and nonces/hashes are not judged.
- Fixtures `remote-importscripts` and `bad-csp` plus unit and end-to-end tests for both.
- This changelog.

### Changed
- README and `--help` list the new checks (12 rules).
- Synced `package-lock.json` to the package version.

### Validation
- 0 new findings and 0 crashes across the 106-extension sample corpus and the 7 real
  minified release extensions.
