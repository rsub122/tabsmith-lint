import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { probablePackage } from "../src/rules/mv3.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });
const sw = (code: string) =>
  analyzeExt({ "manifest.json": mv3({ background: { service_worker: "bg.js" } }), "bg.js": code });
const cs = (code: string, rel = "cs.js") =>
  analyzeExt({ "manifest.json": mv3({ content_scripts: [{ matches: ["https://example.com/*"], js: [rel] }] }), [rel]: code });
const byRule = (r: ReturnType<typeof sw>, id: string) => r.findings.filter((f) => f.ruleId === id);

describe("MV3001: chrome.scripting with remote files", () => {
  it.each([
    'chrome.scripting.executeScript({ target: { tabId: 1 }, files: ["https://cdn.example.com/a.js"] });',
    'browser.scripting.executeScript({ target: { tabId: 1 }, files: ["local.js", "//cdn.example.com/a.js"] });',
    "chrome.scripting.executeScript({ target: { tabId: 1 }, files: [`http://cdn.example.com/a.js`] });",
    'chrome.scripting.registerContentScripts([{ id: "x", matches: ["<all_urls>"], js: ["https://cdn.example.com/a.js"] }]);',
    'chrome.scripting.updateContentScripts([{ id: "x", js: ["https://cdn.example.com/a.js"] }]);',
    'await chrome?.scripting?.executeScript({ target: { tabId: 1 }, "files": ["https://cdn.example.com/a.js"] });',
  ])("flags %s", (code) => {
    const f = byRule(sw(code), "MV3001");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("reject");
    expect(f[0].chromeViolationId).toBe("Blue Argon");
    expect(f[0].title).toContain("chrome.scripting");
    expect(f[0].message).toContain("cdn.example.com/a.js");
  });

  it("reports one finding per remote entry", () => {
    const r = sw('chrome.scripting.registerContentScripts([{ id: "a", js: ["https://a.example/a.js"] }, { id: "b", js: ["https://b.example/b.js", "ok.js"] }]);');
    expect(byRule(r, "MV3001").length).toBe(2);
  });

  it.each([
    'chrome.scripting.executeScript({ target: { tabId: 1 }, files: ["content.js", "/lib/x.js"] });',
    "chrome.scripting.executeScript({ target: { tabId: 1 }, files: list });",
    "chrome.scripting.executeScript({ target: { tabId: 1 }, files: [`https://${host}/a.js`] });",
    'chrome.scripting.executeScript({ target: { tabId: 1 }, func: () => fetch("https://api.example.com/a.json") });',
    'chrome.scripting.insertCSS({ target: { tabId: 1 }, files: ["https://cdn.example.com/a.css"] });',
    'chrome.scripting.registerContentScripts([{ id: "x", matches: ["https://example.com/*"], css: ["https://cdn.example.com/a.css"], js: ["c.js"] }]);',
    'other.executeScript({ files: ["https://cdn.example.com/a.js"] });',
  ])("does not flag %s", (code) => {
    expect(byRule(sw(code), "MV3001")).toEqual([]);
  });
});

describe("MV3005: latent remote-code loaders", () => {
  it("computed script src + remote .js literal in the same file → fix, names the URL and the package", () => {
    const code = `/*! acme-widget v2.4.1 */
var URL1 = "https://cdn.acme.example/recorder.min.js";
function load(u) { var s = document.createElement("script"); s.src = u || URL1; document.head.appendChild(s); }`;
    const f = byRule(cs(code), "MV3005");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].chromeViolationId).toBe("Blue Argon");
    expect(f[0].line).toBe(3);
    expect(f[0].message).toContain("https://cdn.acme.example/recorder.min.js");
    expect(f[0].message).toContain("acme-widget@2.4.1");
  });

  it.each([
    'const s = document.createElement("script"); s.src = `https://${host}/a.js`;',
    'const s = document.createElement("script"); s.src = "https://cdn.example.com/" + name;',
    'const s = document.createElement("script"); s.setAttribute("src", "//cdn.example.com/" + v + ".js");',
    'document.head.append(Object.assign(document.createElement("script"), { src: `https://cdn.example.com/${v}` }));',
    "importScripts(`https://cdn.example.com/${v}.js`);",
  ])("computed URL with a remote prefix → fix: %s", (code) => {
    const f = byRule(sw(code), "MV3005");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].message).toContain("remote prefix");
    expect(byRule(sw(code), "MV3001")).toEqual([]); // literal-only rule stays quiet
  });

  it("computed importScripts + remote .js literal → fix", () => {
    const f = byRule(sw('const CDN = "https://cdn.example.com/lib.js"; importScripts(pick(CDN));'), "MV3005");
    expect(f.map((x) => x.severity)).toEqual(["fix"]);
  });

  it("a remote .js literal alone → one info finding per file (verdict unaffected)", () => {
    const r = cs('const a = "https://cdn.example.com/a.js"; const b = "https://cdn.example.com/b.mjs?v=2"; const c = "https://cdn.example.com/a.js";');
    const f = byRule(r, "MV3005");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].message).toContain("https://cdn.example.com/a.js");
    expect(f[0].message).toContain("b.mjs?v=2");
    expect(r.verdict).toBe("pass");
  });

  it.each([
    // remote data / non-script URLs
    'fetch("https://api.example.com/data.json").then((r) => r.json());',
    'const u = "https://api.example.com/v1/config"; fetch(u);',
    'const css = "https://cdn.example.com/a.css"; const img = "https://cdn.example.com/a.png";',
    'const doc = "https://github.com/acme/widget/blob/main/src/loader.js";',
    '// see https://cdn.example.com/a.js\nconst x = 1;',
    'const s = "load https://cdn.example.com/a.js later";',
    // computed src with no remote .js anywhere in the file
    'const s = document.createElement("script"); s.src = chrome.runtime.getURL("inject.js");',
    'const s = document.createElement("script"); s.src = cfg.url; fetch("https://api.example.com/x.json");',
    'const s = document.createElement("script"); s.src = base + "/inject.js";',
    "importScripts(...LOCAL_SCRIPTS);",
  ])("does not flag %s", (code) => {
    expect(byRule(cs(code), "MV3005")).toEqual([]);
  });

  it("computed src on a non-script element is not a loader (the literal alone stays info)", () => {
    const f = byRule(cs('const URL1 = "https://cdn.example.com/a.js"; const i = document.createElement("img"); i.src = pick(URL1);'), "MV3005");
    expect(f.map((x) => x.severity)).toEqual(["info"]);
  });

  it("getURL src is local even next to a remote .js literal (only the literal is reported, at info)", () => {
    const f = byRule(cs('const R = "https://cdn.example.com/a.js"; const s = document.createElement("script"); s.src = chrome.runtime.getURL("x.js");'), "MV3005");
    expect(f.map((x) => x.severity)).toEqual(["info"]);
  });

  it("URLs already reported by MV3001 are not repeated by MV3005", () => {
    const r = cs('const s = document.createElement("script"); s.src = "https://cdn.example.com/a.js";');
    expect(byRule(r, "MV3001").length).toBe(1);
    expect(byRule(r, "MV3005")).toEqual([]);
    const r2 = sw('importScripts("https://cdn.example.com/a.js");');
    expect(byRule(r2, "MV3005")).toEqual([]);
  });

  it("probablePackage: banner or vendor path, else null", () => {
    expect(probablePackage("x.js", "/*! rrweb v2.0.0-alpha.4 | MIT */\nvar a;")).toBe("rrweb@2.0.0-alpha.4");
    expect(probablePackage("x.js", "/** @license posthog-js 1.200.1 */")).toBe("posthog-js@1.200.1");
    expect(probablePackage("js/vendor/recorder.min.js", "var a;")).toBe("recorder");
    expect(probablePackage("src/app.js", "var a;")).toBeNull();
  });
});

describe("MV3005: one fix finding per file", () => {
  it("several loaders in one file → one finding that lists the other lines", () => {
    const code = `var LIB = "//cdn.example.com/lib.min.js";
var s = document.createElement("script");
if (a) {
  s.src = CUSTOM;
} else if (b) {
  s.src = "https:" + LIB;
} else {
  s.src = LIB;
}`;
    const f = analyzeExt({
      "manifest.json": mv3({ content_scripts: [{ matches: ["https://example.com/*"], js: ["cs.js"] }] }),
      "cs.js": code,
    }).findings.filter((x) => x.ruleId === "MV3005");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].line).toBe(4);
    expect(f[0].message).toContain("Other script loads in this file: lines 6, 8.");
  });
});
