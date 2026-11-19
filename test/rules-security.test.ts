import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";

const BROAD = ["<all_urls>"];
const ext = (rules: object[], opts: { hosts?: string[]; enabled?: boolean; extra?: Record<string, string | object> } = {}) =>
  analyzeExt({
    "manifest.json": {
      manifest_version: 3,
      name: "t",
      version: "1.0.0",
      permissions: ["declarativeNetRequest"],
      host_permissions: opts.hosts ?? BROAD,
      declarative_net_request: { rule_resources: [{ id: "r", enabled: opts.enabled ?? true, path: "rules.json" }] },
    },
    "rules.json": JSON.stringify(rules, null, 2),
    ...(opts.extra ?? {}),
  });
const sec = (r: ReturnType<typeof ext>) => r.findings.filter((f) => f.ruleId === "SEC001");
const rule = (responseHeaders: object[], condition: object = { resourceTypes: ["main_frame", "sub_frame"] }, id = 1) => ({
  id,
  priority: 1,
  action: { type: "modifyHeaders", responseHeaders },
  condition,
});

describe("SEC001: DNR rules that strip security headers", () => {
  it.each([
    ["content-security-policy", "remove"],
    ["Content-Security-Policy", "remove"],
    ["content-security-policy-report-only", "remove"],
    ["x-frame-options", "remove"],
    ["cross-origin-opener-policy", "set"],
    ["cross-origin-embedder-policy", "remove"],
    ["cross-origin-resource-policy", "remove"],
    ["strict-transport-security", "set"],
  ])("broad rule that %s/%s → fix", (header, operation) => {
    const f = sec(ext([rule([{ header, operation, value: "x" }])]));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].confidence).toBe("high");
    expect(f[0].file).toBe("rules.json");
    expect(f[0].line).toBe(3);
    expect(f[0].message).toContain(header);
  });

  it.each([
    [{ urlFilter: "*" }],
    [{ urlFilter: "|http" }],
    [{ urlFilter: "|https://*" }],
    [{ regexFilter: "^https?://.*" }],
    [{}],
  ])("broad condition %j → fix", (condition) => {
    expect(sec(ext([rule([{ header: "x-frame-options", operation: "remove" }], condition)]))[0]?.severity).toBe("fix");
  });

  it.each([
    [{ requestDomains: ["example.com"] }],
    [{ initiatorDomains: ["app.example.com"] }],
    [{ urlFilter: "||example.com/embed" }],
    [{ urlFilter: "|https://docs.example.com/" }],
    [{ regexFilter: "^https://([a-z]+\\.)?example\\.com/" }],
  ])("scoped condition %j → info", (condition) => {
    const f = sec(ext([rule([{ header: "content-security-policy", operation: "remove" }], condition)]));
    expect(f.map((x) => x.severity)).toEqual(["info"]);
  });

  it("broad condition but narrow host access → info", () => {
    const f = sec(ext([rule([{ header: "x-frame-options", operation: "remove" }])], { hosts: ["https://example.com/*"] }));
    expect(f.map((x) => x.severity)).toEqual(["info"]);
  });

  it("optional broad host access still counts as broad", () => {
    const r = analyzeExt({
      "manifest.json": {
        manifest_version: 3, name: "t", version: "1.0.0", permissions: ["declarativeNetRequest"],
        optional_host_permissions: ["*://*/*"],
        declarative_net_request: { rule_resources: [{ id: "r", enabled: true, path: "rules.json" }] },
      },
      "rules.json": JSON.stringify([rule([{ header: "x-frame-options", operation: "remove" }])]),
    });
    expect(sec(r).map((x) => x.severity)).toEqual(["fix"]);
  });

  it("disabled-by-default ruleset is still reported and says so", () => {
    const f = sec(ext([rule([{ header: "x-frame-options", operation: "remove" }])], { enabled: false }));
    expect(f.length).toBe(1);
    expect(f[0].message).toContain("disabled by default");
  });

  it.each([
    ["append to a CSP", [{ header: "content-security-policy", operation: "append", value: "frame-ancestors 'self'" }]],
    ["non-security header", [{ header: "cache-control", operation: "remove" }]],
    ["set-cookie removal", [{ header: "set-cookie", operation: "remove" }]],
  ])("does not flag %s", (_label, headers) => {
    expect(sec(ext([rule(headers as object[])]))).toEqual([]);
  });

  it("does not flag request-header changes, block rules, or invalid/missing rule files", () => {
    const req = { id: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "content-security-policy", operation: "remove" }] }, condition: {} };
    const block = { id: 2, action: { type: "block" }, condition: { urlFilter: "ads" } };
    expect(sec(ext([req, block]))).toEqual([]);
    const bad = analyzeExt({
      "manifest.json": {
        manifest_version: 3, name: "t", version: "1.0.0", permissions: ["declarativeNetRequest"], host_permissions: BROAD,
        declarative_net_request: { rule_resources: [{ id: "a", enabled: true, path: "bad.json" }, { id: "b", enabled: true, path: "../outside.json" }] },
      },
      "bad.json": "{ not json",
    });
    expect(sec(bad)).toEqual([]);
  });

  it("reports the right rule line when there are several rules", () => {
    const f = sec(ext([
      { id: 7, action: { type: "block" }, condition: { urlFilter: "ads" } },
      rule([{ header: "x-frame-options", operation: "remove" }], {}, 8),
    ]));
    expect(f.length).toBe(1);
    expect(f[0].message).toContain("DNR rule 8");
    expect(f[0].line).toBe(12); // the `"id": 8` line
  });

  it("literal rules in updateDynamicRules / updateSessionRules are judged", () => {
    const r = analyzeExt({
      "manifest.json": { manifest_version: 3, name: "t", version: "1.0.0", permissions: ["declarativeNetRequest"], host_permissions: BROAD, background: { service_worker: "bg.js" } },
      "bg.js": `chrome.declarativeNetRequest.updateDynamicRules({
  removeRuleIds: [1],
  addRules: [{ id: 1, action: { type: "modifyHeaders", responseHeaders: [{ header: "x-frame-options", operation: "remove" }] }, condition: { urlFilter: "*" } }],
});
chrome.declarativeNetRequest.updateSessionRules({ addRules: [{ id: 2, action: { type: "modifyHeaders", responseHeaders: [{ header: "content-security-policy", operation: "remove" }] }, condition: { requestDomains: ["example.com"] } }] });
chrome.declarativeNetRequest.updateDynamicRules({ addRules: rulesFromStorage });`,
    });
    const f = sec(r);
    expect(f.map((x) => [x.severity, x.file, x.line])).toEqual([["fix", "bg.js", 1], ["info", "bg.js", 5]]);
    expect(f[0].message).toContain("updateDynamicRules");
  });
});
