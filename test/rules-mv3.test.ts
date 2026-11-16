import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { ruleIds } from "./helpers.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });

describe("U8: MV3 rules", () => {
  it("import('https://...') → MV3001", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "import('https://example.com/app.js');",
    });
    expect(ruleIds(r)).toContain("MV3001");
  });

  it("new Function(...) → MV3002", () => {
    const r = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "const f = new Function('return 1');",
    });
    expect(ruleIds(r)).toContain("MV3002");
  });

  it('setTimeout("run()", 100) → MV3002 but setTimeout(() => run(), 100) → no MV3002', () => {
    const bad = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "setTimeout('run()', 100);",
    });
    expect(ruleIds(bad)).toContain("MV3002");

    const good = analyzeExt({
      "manifest.json": mv3({ background: { service_worker: "bg.js" } }),
      "bg.js": "setTimeout(() => run(), 100);",
    });
    expect(ruleIds(good)).not.toContain("MV3002");
  });

  it("manifest_version 2 → MV3003 + exit-equivalent high_rejection_risk", () => {
    const r = analyzeExt({ "manifest.json": { manifest_version: 2, name: "t", version: "1.0.0" } });
    expect(ruleIds(r)).toContain("MV3003");
    expect(r.verdict).toBe("high_rejection_risk");
  });

  describe("MV3001: importScripts with a remote URL", () => {
    const sw = (code: string) =>
      analyzeExt({ "manifest.json": mv3({ background: { service_worker: "bg.js" } }), "bg.js": code });

    it.each([
      'importScripts("https://example.com/a.js");',
      "importScripts('//example.com/a.js');",
      "importScripts(`http://example.com/a.js`);",
      'self.importScripts("local.js", "https://example.com/a.js");',
      'globalThis.importScripts("https://example.com/a.js");',
    ])("flags %s", (code) => {
      const r = sw(code);
      const f = r.findings.filter((x) => x.ruleId === "MV3001");
      expect(f.length).toBe(1);
      expect(f[0].severity).toBe("reject");
      expect(f[0].message).toContain("importScripts");
      expect(f[0].chromeViolationId).toBe("Blue Argon");
      expect(r.verdict).toBe("high_rejection_risk");
    });

    it.each([
      'importScripts("local.js", "/lib/util.js");',
      "importScripts(urlFromConfig);",
      "importScripts(`https://${host}/a.js`);",
      'other.importScripts("https://example.com/a.js");',
      'const importScripts = (u) => u; importScripts("local.js");',
    ])("does not flag %s", (code) => {
      expect(ruleIds(sw(code))).not.toContain("MV3001");
    });
  });

  describe("MV3001: remote src on a JS-created <script> element", () => {
    const cs = (code: string) =>
      analyzeExt({
        "manifest.json": mv3({ content_scripts: [{ matches: ["https://example.com/*"], js: ["cs.js"] }] }),
        "cs.js": code,
      });
    const mv3001 = (code: string) => cs(code).findings.filter((x) => x.ruleId === "MV3001");

    it.each([
      'const s = document.createElement("script"); s.src = "https://cdn.example.com/a.js"; document.head.appendChild(s);',
      "var s = document.createElement('SCRIPT'); s.src = '//cdn.example.com/a.js';",
      'let s; s = document.createElement("script"); s.setAttribute("src", "http://cdn.example.com/a.js");',
      'const el = window.document.createElement(`script`); el["src"] = `https://cdn.example.com/a.js`;',
      'document.createElement("script").src = "https://cdn.example.com/a.js";',
      'document.head.append(Object.assign(document.createElement("script"), { src: "https://cdn.example.com/a.js" }));',
      'function inject() { const tag = node.ownerDocument.createElement("script"); tag.setAttribute("SRC", "https://cdn.example.com/a.js"); }',
    ])("flags %s", (code) => {
      const f = mv3001(code);
      expect(f.length).toBe(1);
      expect(f[0].severity).toBe("reject");
      expect(f[0].chromeViolationId).toBe("Blue Argon");
      expect(f[0].message).toContain("cdn.example.com/a.js");
      expect(f[0].fixHint).toContain("remote JSON/data is allowed");
      expect(f[0].line).toBe(1);
    });

    it.each([
      // remote data, not code
      'fetch("https://api.example.com/data.json").then((r) => r.json());',
      'const x = new XMLHttpRequest(); x.open("GET", "https://api.example.com/data.json"); x.send();',
      // non-script elements
      'const img = document.createElement("img"); img.src = "https://cdn.example.com/a.png";',
      'const f = document.createElement("iframe"); f.src = "https://example.com/embed";',
      'const f = document.createElement("iframe"); f.setAttribute("src", "https://example.com/embed");',
      'const l = document.createElement("link"); l.href = "https://cdn.example.com/a.css";',
      'new Image().src = "https://cdn.example.com/pixel.gif";',
      // local / computed URLs
      'const s = document.createElement("script"); s.src = chrome.runtime.getURL("inject.js");',
      'const s = document.createElement("script"); s.src = "inject.js";',
      'const s = document.createElement("script"); s.src = "/lib/inject.js";',
      'const s = document.createElement("script"); s.src = `https://${host}/a.js`;',
      'const s = document.createElement("script"); s.src = "https://cdn.example.com/" + name;',
      'const s = document.createElement("script"); s.src = cfg.url;',
      'const s = document.createElement("script"); s.textContent = "https://example.com/a.js";',
      'const s = document.createElement("script"); s.setAttribute("data-src", "https://cdn.example.com/a.js");',
      // a name reused for a non-script element is not tracked (no guessing)
      'function a() { const s = document.createElement("script"); s.src = "local.js"; } function b() { const s = document.createElement("img"); s.src = "https://cdn.example.com/a.png"; }',
      'function a() { const s = document.createElement("script"); } function b(s) { s.src = "https://cdn.example.com/a.png"; }',
      // not a DOM document / not createElement
      'const s = React.createElement("script"); s.src = "https://cdn.example.com/a.js";',
      'const s = document.createElementNS(ns, "img"); s.src = "https://cdn.example.com/a.js";',
      'const s = document.createElement(tagName); s.src = "https://cdn.example.com/a.js";',
      // comparisons and reads are not assignments
      'const s = document.createElement("script"); if (s.src === "https://cdn.example.com/a.js") {}',
    ])("does not flag %s", (code) => {
      expect(mv3001(code)).toEqual([]);
    });
  });

  describe("MV3004: extension_pages CSP", () => {
    const withCsp = (content_security_policy: unknown, manifest_version = 3) =>
      analyzeExt({ "manifest.json": { manifest_version, name: "t", version: "1.0.0", content_security_policy } });

    it("string-form CSP in MV3 → reject", () => {
      const r = withCsp("script-src 'self'; object-src 'self'");
      const f = r.findings.filter((x) => x.ruleId === "MV3004");
      expect(f.length).toBe(1);
      expect(f[0].severity).toBe("reject");
      expect(f[0].title).toMatch(/must be an object/);
      expect(r.verdict).toBe("high_rejection_risk");
    });

    it.each([
      "script-src 'self' 'unsafe-eval'; object-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "script-src 'self' https://cdn.example.com",
      "script-src 'self' *",
      "script-src 'self' https:",
      "object-src 'self' https://evil.example.com",
      "worker-src 'self' blob:",
    ])("flags extension_pages %s", (pages) => {
      const r = withCsp({ extension_pages: pages });
      expect(ruleIds(r)).toContain("MV3004");
      expect(r.findings.find((x) => x.ruleId === "MV3004")!.chromeViolationId).toBe("Blue Argon");
    });

    it.each([
      "script-src 'self'; object-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
      "script-src 'self' http://localhost:* http://127.0.0.1:8080; object-src 'self'",
      "script-src 'self'; connect-src https://api.example.com; img-src https: data:",
      "default-src 'self'",
    ])("allows extension_pages %s", (pages) => {
      expect(ruleIds(withCsp({ extension_pages: pages }))).not.toContain("MV3004");
    });

    it("never inspects the sandbox policy", () => {
      const r = withCsp({
        extension_pages: "script-src 'self'; object-src 'self'",
        sandbox: "sandbox allow-scripts; script-src 'self' 'unsafe-eval' https://cdn.example.com",
      });
      expect(ruleIds(r)).not.toContain("MV3004");
    });

    it("no CSP, odd shapes, and MV2 manifests produce nothing", () => {
      expect(ruleIds(withCsp(undefined))).not.toContain("MV3004");
      expect(ruleIds(withCsp({}))).not.toContain("MV3004");
      expect(ruleIds(withCsp({ extension_pages: 42 }))).not.toContain("MV3004");
      expect(ruleIds(withCsp(null))).not.toContain("MV3004");
      expect(ruleIds(withCsp("script-src 'self' 'unsafe-eval'", 2))).not.toContain("MV3004");
    });
  });
});
