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
