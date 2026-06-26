import { describe, it, expect } from "vitest";
import { extractFromScripts } from "../src/parse/extract-api-calls.js";
import { script } from "./helpers.js";

function extract(source: string) {
  return extractFromScripts([script(source)]);
}

describe("U5: API-call extraction", () => {
  it("chrome.storage.local.get → ApiCall(storage, high confidence)", () => {
    const { apiCalls } = extract("chrome.storage.local.get('k');");
    const call = apiCalls.find((c) => c.namespace === "storage");
    expect(call).toBeTruthy();
    expect(call!.confidence).toBe("high");
    expect(call!.path).toEqual(["storage", "local", "get"]);
  });

  it("optional chaining chrome?.storage?.local?.get → same extraction", () => {
    const { apiCalls } = extract("chrome?.storage?.local?.get('k');");
    expect(apiCalls.some((c) => c.namespace === "storage")).toBe(true);
  });

  it("alias: const s = chrome.storage; s.local.get() → storage detected", () => {
    const { apiCalls } = extract("const s = chrome.storage; s.local.get('k');");
    expect(apiCalls.some((c) => c.namespace === "storage")).toBe(true);
  });

  it("destructure: const { storage } = chrome; storage.local.get() → storage detected", () => {
    const { apiCalls } = extract("const { storage } = chrome; storage.local.get('k');");
    expect(apiCalls.some((c) => c.namespace === "storage")).toBe(true);
  });

  it("cross-browser polyfill alias (const api = globalThis.browser || globalThis.chrome) resolves", () => {
    const { apiCalls } = extract("const api = globalThis.browser || globalThis.chrome; api.storage.local.get('k');");
    expect(apiCalls.some((c) => c.namespace === "storage")).toBe(true);
  });

  it("conditional polyfill alias (typeof browser !== 'undefined' ? browser : chrome) resolves", () => {
    const { apiCalls } = extract("const api = typeof browser !== 'undefined' ? browser : chrome; api.webRequest.onBeforeRequest.addListener(()=>{});");
    expect(apiCalls.some((c) => c.namespace === "webRequest")).toBe(true);
  });

  it("browser.* polyfill global is detected", () => {
    const { apiCalls } = extract("browser.tabs.query({});");
    const call = apiCalls.find((c) => c.namespace === "tabs");
    expect(call?.root).toBe("browser");
  });

  it("dynamic chrome[name].get() → recorded as dynamic access, not a concrete call", () => {
    const { apiCalls, dynamicApiAccess } = extract("chrome[name].get();");
    expect(dynamicApiAccess.length).toBeGreaterThan(0);
    expect(apiCalls.length).toBe(0);
  });

  it("reading tab.url after a tabs query → SensitiveTabRead", () => {
    const { sensitiveTabReads } = extract(
      "chrome.tabs.query({active:true}, (tabs) => { const tab = tabs[0]; console.log(tab.url); });"
    );
    expect(sensitiveTabReads.some((r) => r.property === "url")).toBe(true);
  });

  it("cross-origin fetch → HostAccessSignal", () => {
    const { hostAccessSignals } = extract("fetch('https://example.com/x');");
    expect(hostAccessSignals.some((h) => h.kind === "fetch")).toBe(true);
  });
});
