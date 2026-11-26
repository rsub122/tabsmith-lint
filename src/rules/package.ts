import type { ExtensionModel, Finding, Severity, Confidence } from "../engine/model.js";
import { findLine } from "../engine/source-lines.js";

// Package hygiene: what is inside the .zip/.crx you actually upload.
//  PKG001 — files that should not ship (secrets, VCS metadata, node_modules,
//           private keys, unsafe entry paths at `fix`; source maps, tests and OS
//           junk at `info`). Runs on .zip/.crx input only: an unpacked SOURCE
//           directory normally contains node_modules/.git/tests that never get
//           zipped, so judging a directory would be all false positives.
//  PKG002 — "key" left in manifest.json (`info`, any input). It pins a stable ID
//           for unpacked development; the store assigns the published ID.
//  PKG003 — archive larger than the Chrome Web Store's 2 GB package limit
//           ("Zip files larger than 2GB will be rejected") → `reject`; within
//           10% of it → `info`.

export const PACKAGE_LIMIT_BYTES = 2 * 1024 * 1024 * 1024;
const NEAR_LIMIT_BYTES = Math.floor(PACKAGE_LIMIT_BYTES * 0.9);
const SHOW_PATHS = 5;

interface Category {
  id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  why: string;
  fixHint: string;
  match: (relPath: string, segs: string[], base: string) => boolean;
}

// "spec" is deliberately absent: editors ship runtime language modes in folders
// named spec (CodeMirror mode/rpm/spec/spec.js), found on the samples corpus.
const TEST_DIRS = new Set(["test", "tests", "__tests__", "__mocks__", "e2e", "cypress"]);
const VCS_DIRS = new Set([".git", ".svn", ".hg"]);
const OS_JUNK = new Set([".ds_store", "thumbs.db", "desktop.ini"]);

const CATEGORIES: Category[] = [
  {
    id: "env",
    severity: "fix",
    confidence: "high",
    title: ".env file(s) in the package",
    why: "Environment files usually hold API keys and other secrets; anything in the package is public to every user who installs it.",
    fixHint: "Remove .env* files from the zip (and rotate any secret that already shipped). Inject build-time values instead.",
    match: (_r, _s, base) => /^\.env(\..+)?$/i.test(base),
  },
  {
    id: "key",
    severity: "fix",
    confidence: "high",
    title: "Private key (.pem) in the package",
    why: "A .pem file is typically the extension's CRX signing key or another private key; shipping it exposes it publicly.",
    fixHint: "Remove the .pem from the zip and keep it outside the extension folder. If it is a signing key that shipped, treat it as compromised.",
    match: (_r, _s, base) => /\.pem$/i.test(base),
  },
  {
    id: "vcs",
    severity: "fix",
    confidence: "high",
    title: "Version-control metadata in the package",
    why: "A .git/.svn/.hg folder ships your repository history (possibly including removed secrets) and bloats the upload.",
    fixHint: "Zip the build output, not the repository checkout; exclude .git/.svn/.hg.",
    match: (_r, segs) => segs.slice(0, -1).some((s) => VCS_DIRS.has(s)),
  },
  {
    id: "node_modules",
    severity: "fix",
    confidence: "high",
    title: "node_modules/ in the package",
    why: "node_modules is development input: it bloats the package and ships code reviewers must audit, including dependencies the extension never loads.",
    fixHint: "Bundle what you use (esbuild/Vite/webpack) or copy the specific files into your build output, then zip only the output.",
    match: (_r, segs) => segs.slice(0, -1).includes("node_modules"),
  },
  {
    id: "sourcemap",
    severity: "info",
    confidence: "high",
    title: "Source maps in the package",
    why: "Source maps are allowed, but they publish your original source and add size. Keep them only if that is intentional (they can help reviewers read minified code).",
    fixHint: "Disable production source maps or strip *.map files from the zip if you do not mean to ship them.",
    match: (_r, _s, base) => /\.map$/i.test(base),
  },
  {
    id: "tests",
    severity: "info",
    confidence: "medium",
    title: "Test files in the package",
    why: "Test files and fixtures are not used at runtime; they add size and code for reviewers to read.",
    fixHint: "Exclude test/spec files and folders from the zip.",
    match: (_r, segs, base) =>
      segs.slice(0, -1).some((s) => TEST_DIRS.has(s.toLowerCase())) || /\.(test|spec)\.[cm]?[jt]sx?$/i.test(base),
  },
  {
    id: "junk",
    severity: "info",
    confidence: "high",
    title: "OS junk files in the package",
    why: "Finder/Explorer metadata (.DS_Store, __MACOSX/, Thumbs.db) is clutter that ships to every user.",
    fixHint: "Zip with `zip -r ext.zip . -x '.DS_Store' '__MACOSX/*'` or your build tool, or delete these files before zipping.",
    match: (_r, segs, base) => OS_JUNK.has(base.toLowerCase()) || segs[0] === "__MACOSX",
  },
];

function listPaths(paths: string[]): string {
  const shown = paths.slice(0, SHOW_PATHS).join(", ");
  return paths.length > SHOW_PATHS ? `${shown} (+${paths.length - SHOW_PATHS} more)` : shown;
}

/** Files the extension actually loads (manifest entries and the scripts their
 *  pages include). A referenced file is never reported as "should not ship". */
function referencedPaths(model: ExtensionModel): Set<string> {
  const out = new Set<string>();
  for (const r of model.manifestRefs) out.add(r.ref.replace(/^[\\/]+/, ""));
  for (const f of model.files) if (f.discoveredBy === "manifest") out.add(f.relPath);
  return out;
}

function packageContents(model: ExtensionModel): Finding[] {
  const pkg = model.package;
  if (!pkg) return [];
  const findings: Finding[] = [];
  const referenced = referencedPaths(model);
  const claimed = new Set<string>();

  for (const cat of CATEGORIES) {
    const hits: string[] = [];
    const used: string[] = [];
    for (const f of pkg.files) {
      if (claimed.has(f.relPath)) continue;
      const segs = f.relPath.split("/");
      if (!cat.match(f.relPath, segs, segs[segs.length - 1])) continue;
      claimed.add(f.relPath);
      (referenced.has(f.relPath) ? used : hits).push(f.relPath);
    }
    if (hits.length === 0) continue;
    // node_modules the extension really loads (e.g. a polyfill referenced from the
    // manifest): removing the folder would break it, so only advise.
    const severity: Severity = cat.id === "node_modules" && used.length > 0 ? "info" : cat.severity;
    const usedNote = used.length ? ` ${used.length} referenced file(s) there are loaded by the extension (${listPaths(used)}); move them into your build output before dropping the rest.` : "";
    findings.push({
      ruleId: "PKG001",
      severity,
      confidence: cat.confidence,
      title: cat.title,
      message: `${hits.length} file(s): ${listPaths(hits)}. ${cat.why}${usedNote}`,
      file: hits[0],
      fixHint: cat.fixHint,
    });
  }

  if (pkg.unsafePaths.length) {
    findings.push({
      ruleId: "PKG001",
      severity: "fix",
      confidence: "high",
      title: "Archive entries with unsafe paths",
      message: `${pkg.unsafePaths.length} entr${pkg.unsafePaths.length === 1 ? "y" : "ies"} escape the package root and were skipped: ${listPaths(pkg.unsafePaths)}. Absolute or "../" paths are not valid in an extension package.`,
      fixHint: "Re-create the zip from inside the extension folder with relative paths only.",
    });
  }
  return findings;
}

function manifestKey(model: ExtensionModel): Finding[] {
  if (!Object.prototype.hasOwnProperty.call(model.manifest, "key")) return [];
  return [
    {
      ruleId: "PKG002",
      severity: "info",
      confidence: "high",
      title: `"key" is set in manifest.json`,
      message: `The "key" field pins a stable extension ID for unpacked development. The Chrome Web Store assigns the published item its own ID and key, so this is normally a development leftover.`,
      file: "manifest.json",
      line: findLine(model.manifestRaw, `"key"`),
      fixHint: `Remove "key" from the manifest in the package you upload (keep it only in your development manifest).`,
    },
  ];
}

function gb(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
}

function packageSize(model: ExtensionModel): Finding[] {
  const pkg = model.package;
  if (!pkg) return [];
  if (pkg.archiveBytes > PACKAGE_LIMIT_BYTES) {
    return [
      {
        ruleId: "PKG003",
        severity: "reject",
        confidence: "high",
        title: "Package exceeds the Chrome Web Store 2 GB limit",
        message: `The archive is ${gb(pkg.archiveBytes)}. The maximum supported package size is 2GB; larger zip files are rejected at upload.`,
        fixHint: "Drop unused assets (and anything PKG001 lists), compress media, or download large data at runtime as data (not code).",
      },
    ];
  }
  if (pkg.archiveBytes > NEAR_LIMIT_BYTES) {
    return [
      {
        ruleId: "PKG003",
        severity: "info",
        confidence: "high",
        title: "Package is close to the Chrome Web Store 2 GB limit",
        message: `The archive is ${gb(pkg.archiveBytes)}, within 10% of the 2GB package limit.`,
        fixHint: "Trim unused assets before the next release pushes it over the limit.",
      },
    ];
  }
  return [];
}

export const packageRules = [packageContents, manifestKey, packageSize];
