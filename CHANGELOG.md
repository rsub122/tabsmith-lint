# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
