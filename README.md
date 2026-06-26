# tabsmith-lint

A pre-submission compliance linter for browser extensions. v0.1 analyzes an unpacked
Manifest V3 Chrome extension directory and reports likely Chrome Web Store rejection
risks **before** you submit — unused/excessive permissions, missing permissions, MV3
violations, and broken file references — with a clear verdict and actionable fixes.

**Catch the "Purple Potassium" permission rejection before you submit.** The most
common Chrome Web Store rejection is excessive/unused permissions — declaring `tabs`,
`bookmarks`, `cookies`, or `<all_urls>` your code never actually uses. tabsmith-lint
statically checks your manifest against your code and maps findings to the violations
Chrome reviewers flag:

| Violation ID | What it means | tabsmith rules |
|---|---|---|
| Purple Potassium | Excessive / unused permissions | PERM001, PERM003, PERM004, PERM005 |
| Blue Argon | Remotely hosted code / string execution | MV3001, MV3002 |
| Yellow Magnesium | Functionality / broken packaging | FUNC001, FUNC002 |

```bash
npx tabsmith-lint ./my-extension
npx tabsmith-lint ./my-extension --format json
npx tabsmith-lint ./my-extension --min-severity reject
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

v0.1. Chrome-only, directory input, 10 rules (PERM001-005, MV3001-003, FUNC001-002).

Firefox/Edge, ZIP/CRX input, SARIF, and a GitHub Action are on the roadmap.

Two rules are intentionally conservative in v0.1 (trust is the product): **PERM001**
(unused permission) and **MV3002** (string execution: `eval`/`new Function`) both ship
at `fix` severity, not `reject` — a static linter can't always tell a real problem from
a sandboxed or unreachable one, so they surface for you to verify rather than condemn.
Each is gated behind a single severity constant for later promotion.

## License

MIT — see [LICENSE](LICENSE).
