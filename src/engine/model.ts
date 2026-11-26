// Core types for the tabsmith-lint engine. PRD 6.2 (ExtensionModel/ApiCall) + 4.2 (report schema).

export type Severity = "reject" | "fix" | "info";
export type Confidence = "high" | "medium" | "low";
export type Verdict = "pass" | "needs_fixes" | "high_rejection_risk";

// Loose manifest shape — we only read a handful of fields and never trust the rest.
export interface ManifestJson {
  manifest_version?: number;
  name?: string;
  version?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  [key: string]: unknown;
}

export type DiscoverySource = "manifest" | "fallback";

export interface VirtualFile {
  /** path relative to the extension root, POSIX-style */
  relPath: string;
  absPath: string;
  content: string;
  discoveredBy: DiscoverySource;
}

export interface ScriptFile extends VirtualFile {
  /** babel File AST, or null when parsing failed */
  ast: any | null;
  parseError: boolean;
}

export interface ApiCall {
  root: "chrome" | "browser";
  namespace: string;
  path: string[];
  file: string;
  line?: number;
  column?: number;
  confidence: Confidence;
}

export interface SensitiveTabRead {
  property: "url" | "pendingUrl" | "title" | "favIconUrl";
  file: string;
  line?: number;
}

export interface DynamicApiAccess {
  root: "chrome" | "browser";
  file: string;
  line?: number;
}

export type HostAccessKind =
  | "fetch"
  | "xhr"
  | "cookies"
  | "webRequest"
  | "declarativeNetRequest"
  | "scripting.executeScript"
  | "contentScript";

export interface HostAccessSignal {
  kind: HostAccessKind;
  file: string;
  line?: number;
}

export interface ManifestFileRef {
  /** referenced path as written in the manifest, relative to root */
  ref: string;
  /** manifest key it came from, e.g. "background.service_worker" */
  source: string;
}

/** A static declarativeNetRequest ruleset from declarative_net_request.rule_resources. */
export interface DnrRuleset {
  relPath: string;
  id?: string;
  /** manifest `enabled` flag (static rulesets can still be enabled at runtime) */
  enabled: boolean;
  content: string;
  /** parsed JSON, or null when the file is missing or not valid JSON */
  rules: unknown;
}

export interface ExtensionModel {
  rootDir: string;
  manifest: ManifestJson;
  manifestRaw: string;
  files: VirtualFile[];
  scriptFiles: ScriptFile[];
  htmlFiles: VirtualFile[];
  apiCalls: ApiCall[];
  sensitiveTabReads: SensitiveTabRead[];
  dynamicApiAccess: DynamicApiAccess[];
  hostAccessSignals: HostAccessSignal[];
  manifestRefs: ManifestFileRef[];
  /** Permission names passed to chrome.permissions.request/contains at runtime. */
  runtimeRequestedPermissions: string[];
  /** Static DNR rulesets that exist inside the package and were read. */
  dnrRulesets: DnrRuleset[];
  /** Set only when the input was a .zip/.crx: what actually ships. */
  package?: PackageInfo;
}

/** One file inside an uploaded archive (sizes from the zip central directory). */
export interface PackageFile {
  relPath: string;
  size: number;
  compressedSize: number;
}

export interface PackageInfo {
  kind: "zip" | "crx";
  /** archive size on disk, bytes */
  archiveBytes: number;
  /** every file in the archive, including ones discovery never reads */
  files: PackageFile[];
  /** entry names skipped because they escape the package root ("../x", "/x") */
  unsafePaths: string[];
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  message: string;
  file?: string;
  line?: number;
  column?: number;
  chromeViolationId?: string;
  fixHint?: string;
}

export interface BrowserReport {
  verdict: Verdict;
  findings: Finding[];
  stats: {
    /** present when the input was an archive: number of files in the package */
    packageFiles?: number;
    filesScanned: number;
    scriptsParsed: number;
    parseErrors: number;
  };
}

export interface LintReport {
  tool: "tabsmith-lint";
  version: string;
  inputPath: string;
  manifestVersion?: number;
  browsers: {
    chrome: BrowserReport;
  };
}

/** A rule is a pure function over the model producing zero or more findings. */
export type Rule = (model: ExtensionModel) => Finding[];
