# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
