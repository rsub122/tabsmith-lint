import { existsSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionModel, Finding } from "../engine/model.js";
import { findLine } from "../engine/source-lines.js";
import { isWithinRoot, refToRelPath } from "../engine/file-discovery.js";

// FUNC001 (missing file → reject) + FUNC002 (case-only mismatch → fix).
//
// We compare the manifest reference against actual readdir() entry names with
// case-sensitive string equality, rather than relying on existsSync(). This is
// deliberate: on a case-insensitive filesystem (macOS APFS default) existsSync
// would resolve "Popup.html" to "popup.html" and silently hide the mismatch
// that Chrome's case-sensitive packaging would reject.
function fileRefs(model: ExtensionModel): Finding[] {
  const findings: Finding[] = [];
  for (const ref of model.manifestRefs) {
    // A reference that escapes the package root is invalid packaging — treat it
    // as missing rather than statting an out-of-package path.
    if (!isWithinRoot(model.rootDir, ref.ref)) {
      findings.push({
        ruleId: "FUNC001",
        severity: "reject",
        confidence: "high",
        title: `Manifest reference points outside the package: "${ref.ref}"`,
        message: `"${ref.ref}" (${ref.source}) resolves outside the extension directory and cannot be packaged.`,
        file: "manifest.json",
        line: findLine(model.manifestRaw, ref.ref),
        chromeViolationId: "Yellow Magnesium",
        fixHint: `Use a path inside the extension package for "${ref.source}".`,
      });
      continue;
    }

    const parts = refToRelPath(ref.ref).split("/").filter(Boolean);
    const base = parts.pop()!;
    const parentAbs = join(model.rootDir, ...parts);

    let entries: import("node:fs").Dirent[] = [];
    if (existsSync(parentAbs) && statSync(parentAbs).isDirectory()) {
      entries = readdirSync(parentAbs, { withFileTypes: true });
    }

    const exact = entries.find((e) => e.name === base);
    if (exact?.isFile()) continue;

    const caseMatch = entries.find((e) => e.name.toLowerCase() === base.toLowerCase())?.name;
    const line = findLine(model.manifestRaw, ref.ref);

    if (caseMatch) {
      findings.push({
        ruleId: "FUNC002",
        severity: "fix",
        confidence: "high",
        title: `Case-sensitivity mismatch for "${ref.ref}"`,
        message: `Manifest references "${ref.ref}" (${ref.source}) but the file on disk is "${caseMatch}". Chrome Web Store packaging is case-sensitive.`,
        file: "manifest.json",
        line,
        fixHint: `Rename the file or update the manifest path to match exact case.`,
      });
    } else {
      findings.push({
        ruleId: "FUNC001",
        severity: "reject",
        confidence: "high",
        title: `Manifest-referenced file is missing: "${ref.ref}"`,
        message: `"${ref.ref}" (${ref.source}) is referenced by the manifest but does not exist in the package.`,
        file: "manifest.json",
        line,
        chromeViolationId: "Yellow Magnesium",
        fixHint: `Add the missing file or remove the "${ref.source}" reference.`,
      });
    }
  }
  return findings;
}

export const fileRules = [fileRefs];
