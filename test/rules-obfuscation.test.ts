import { describe, it, expect } from "vitest";
import { analyzeExt } from "./tmp-ext.js";
import { fixtureReport, script } from "./helpers.js";
import {
  obfuscationSignals,
  signalReasons,
  bundledPackageName,
  HEX_IDENT_MIN,
  HEX_LOOKUP_MIN,
  ESCAPED_ASCII_MIN,
} from "../src/rules/obfuscation.js";

const mv3 = (extra: object) => ({ manifest_version: 3, name: "t", version: "1.0.0", ...extra });
const cs = (code: string, rel = "cs.js") =>
  analyzeExt({ "manifest.json": mv3({ content_scripts: [{ matches: ["https://example.com/*"], js: [rel] }] }), [rel]: code });
const obf = (r: ReturnType<typeof cs>) => r.findings.filter((f) => f.ruleId === "OBF001");
const sig = (code: string) => obfuscationSignals(script(code).ast);

// The shape javascript-obfuscator emits: string-array function, rotator IIFE with a parseInt checksum, lookups.
const ROTATOR = `function _0x2d11(){const _0x1a=['log','hello','world','querySelector','body','textContent','push','price'];_0x2d11=function(){return _0x1a;};return _0x2d11();}
(function(_0xc8e5c1,_0xb46e2e){const _0xdaa5db=_0x2d11,_0x584f99=_0xc8e5c1();while(!![]){try{const _0x414b9b=-parseInt('1')/0x1+parseInt('2')/0x2;if(_0x414b9b===_0xb46e2e)break;else _0x584f99['push'](_0x584f99['shift']());}catch(_0x22d182){_0x584f99['push'](_0x584f99['shift']());}}}(_0x2d11,0x1a2b3));`;

const hexIdents = (n: number) => Array.from({ length: n }, (_, i) => `var _0x${(0xa000 + i).toString(16)} = ${i};`).join("\n");
const lookups = (n: number, distinct = n, fn = "d") =>
  `function ${fn}(i){return T[i-0x100];}\n` + Array.from({ length: n }, (_, i) => `${fn}(0x${(0x100 + (i % distinct)).toString(16)});`).join("\n");
const escaped = (n: number) =>
  Array.from({ length: n }, (_, i) => `var s${i} = "${[...`word${i}`].map((c) => "\\x" + c.charCodeAt(0).toString(16)).join("")}";`).join("\n");

describe("OBF001: obfuscated code (Red Titanium)", () => {
  it("fixture: obfuscated vendor file → one fix finding naming the package, first-party file clean", () => {
    const r = fixtureReport("obfuscated-vendor");
    const f = r.findings.filter((x) => x.ruleId === "OBF001");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("fix");
    expect(f[0].confidence).toBe("high");
    expect(f[0].chromeViolationId).toBe("Red Titanium");
    expect(f[0].file).toBe("vendor/price-helper.min.js");
    expect(f[0].line).toBe(1);
    expect(f[0].message).toContain("string-array rotator");
    expect(f[0].message).toContain("_0x-style hexadecimal identifiers");
    expect(f[0].message).toContain("price-helper");
    expect(f[0].fixHint).toContain("price-helper");
    expect(f[0].message).toMatch(/minification is allowed/);
    expect(r.verdict).toBe("needs_fixes");
  });

  it("string-array rotator with a parseInt checksum → fix/high", () => {
    const f = obf(cs(ROTATOR));
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("high");
    expect(f[0].message).toContain("string-array rotator");
  });

  it("legacy rotator with a while(--n) countdown is detected", () => {
    const code = `var _a=['x','y','z'];(function(a,b){var c=function(d){while(--d){a['push'](a['shift']());}};c(++b);}(_a,0x1f3));`;
    expect(sig(code).rotator).toBe(true);
  });

  it.each([
    ["queue rotation in normal code", "function rotate(q){ q.push(q.shift()); return q; }"],
    ["different arrays", "function f(a,b){ while(--n){ a.push(b.shift()); } parseInt(x); parseInt(y); }"],
    [
      "rotation in an inner function, parseInt only in an outer bundle wrapper (Return YouTube Dislike regression)",
      "(function(){ var w = parseInt(a) + parseInt(b); function smooth(cps, loop){ if (loop) { cps.push(cps.shift()); } return cps; } })();",
    ],
  ])("no rotator: %s", (_label, code) => {
    expect(sig(code).rotator).toBe(false);
    expect(obf(cs(code))).toEqual([]);
  });

  it("Dean Edwards packer → fix/high", () => {
    const code = `eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0 1=2;',3,3,'var|x|5'.split('|'),0,{}))`;
    const f = obf(cs(code));
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("high");
    expect(f[0].message).toContain("Dean Edwards packer");
  });

  it.each([
    ['eval(atob("Y29uc29sZS5sb2coMSk="));', "eval(atob())"],
    ["eval(unescape(p));", "eval(unescape())"],
    ["eval(decodeURIComponent(escape(atob(p))));", "eval(decodeURIComponent())"],
    ["Function(atob(p))();", "Function(atob())"],
    ['new Function("a", atob(p));', "new Function(atob())"],
    ["new Function(String.fromCharCode(99, 111, 110))();", "new Function(String.fromCharCode())"],
  ])("code run from a decoded string: %s", (code, label) => {
    const f = obf(cs(code));
    expect(f.length).toBe(1);
    expect(f[0].message).toContain(label);
    expect(f[0].confidence).toBe("medium");
  });

  it.each([
    "eval(code);",
    'new Function("a", "return a");',
    "const s = atob(p); render(s);",
    "eval(JSON.stringify(x));",
    'el.textContent = String.fromCharCode(65, 66);',
    "new Function(atob(p), body);",
  ])("decoding without executing, or executing without decoding, is not OBF001: %s", (code) => {
    expect(obf(cs(code))).toEqual([]);
  });

  it(`_0x identifiers: ${HEX_IDENT_MIN} distinct → flagged, one fewer → not`, () => {
    expect(obf(cs(hexIdents(HEX_IDENT_MIN))).length).toBe(1);
    expect(obf(cs(hexIdents(HEX_IDENT_MIN - 1)))).toEqual([]);
    expect(sig(hexIdents(3) + "\nvar _0xa000 = 1;").hexIdentifiers).toBe(3); // distinct names only
  });

  it(`string-array lookups: ${HEX_LOOKUP_MIN} calls with distinct small hex indices → flagged`, () => {
    const f = obf(cs(lookups(HEX_LOOKUP_MIN)));
    expect(f.length).toBe(1);
    expect(f[0].message).toContain("string-array lookups (d(0x…))");
    expect(obf(cs(lookups(HEX_LOOKUP_MIN - 1)))).toEqual([]);
  });

  it.each([
    ["few distinct values (constant table)", lookups(60, 5)],
    ["hash constants (crypto-js X64Word_create)", Array.from({ length: 40 }, (_, i) => `X64Word_create(0x${(0x428a2f98 + i * 7919).toString(16)}, 0x${(0xd728ae22 + i).toString(16)});`).join("\n")],
    ["colour literals (three.js)", Array.from({ length: 40 }, (_, i) => `color(0x${(0xffb845 - i * 4099).toString(16)});`).join("\n")],
    ["upper-case / zero-padded hex", Array.from({ length: 40 }, (_, i) => `f(0x${(0x100 + i).toString(16).toUpperCase().padStart(4, "0")}A);`).join("\n")],
    ["decimal indices (minifier output)", Array.from({ length: 40 }, (_, i) => `n(${100 + i});`).join("\n")],
    ["method calls", Array.from({ length: 40 }, (_, i) => `a.b(0x${(0x100 + i).toString(16)});`).join("\n")],
  ])("not string-array lookups: %s", (_label, code) => {
    expect(obf(cs(code))).toEqual([]);
  });

  it(`plain-text strings spelled with escapes: ${ESCAPED_ASCII_MIN} → flagged, one fewer → not`, () => {
    const f = obf(cs(escaped(ESCAPED_ASCII_MIN)));
    expect(f.length).toBe(1);
    expect(f[0].message).toContain(`${ESCAPED_ASCII_MIN} plain-text strings spelled with`);
    expect(obf(cs(escaped(ESCAPED_ASCII_MIN - 1)))).toEqual([]);
  });

  it.each([
    ["unicode ranges (lodash/punycode style)", Array.from({ length: 40 }, () => 'var r = "\\u0300-\\u036f\\ufe20-\\ufe2f\\u20d0-\\u20ff";').join("\n")],
    ["control characters", Array.from({ length: 40 }, () => 'var c = "\\x00\\x01\\x02\\x1f";').join("\n")],
    ["non-ASCII text", Array.from({ length: 40 }, () => 'var t = "caf\\u00e9 cr\\u00e8me";').join("\n")],
    ["mostly plain text with one escape", Array.from({ length: 40 }, () => 'var t = "\\x3c/script> tag";').join("\n")],
    ["escapes inside regex literals", Array.from({ length: 40 }, () => "var re = /\\x41\\x42\\x43/;").join("\n")],
  ])("not escaped plain text: %s", (_label, code) => {
    expect(sig(code).escapedAsciiStrings).toBe(0);
    expect(obf(cs(code))).toEqual([]);
  });

  it("several signals → one finding per file, at the first signal's line", () => {
    const code = "// plain header\nconsole.log(1);\n" + ROTATOR + "\n" + hexIdents(20) + "\n" + escaped(25);
    const f = obf(cs(code));
    expect(f.length).toBe(1);
    expect(f[0].line).toBe(3);
    expect(signalReasons(sig(code)).length).toBe(3);
  });

  it("minified (not obfuscated) code is not flagged", () => {
    const min = `!function(t,e){"object"==typeof exports?module.exports=e():t.lib=e()}(this,function(){"use strict";var t=Object.prototype.hasOwnProperty,e=/[\\u0300-\\u036f]/g;function n(n,r){for(var o=0,i=[];o<n.length;o++)t.call(n,o)&&i.push(r(n[o],o));return i}function r(t){return String(t).normalize("NFD").replace(e,"")}return{map:n,deburr:r,chunk:function(t,e){for(var n=[],r=0;r<t.length;r+=e)n.push(t.slice(r,r+e));return n},rotate:function(t){return t.push(t.shift()),t}}});`;
    expect(obf(cs(min))).toEqual([]);
  });

  it("does not change the verdict of clean fixtures", () => {
    expect(fixtureReport("pass-basic-mv3").findings.filter((f) => f.ruleId === "OBF001")).toEqual([]);
    expect(fixtureReport("latent-loader").findings.filter((f) => f.ruleId === "OBF001")).toEqual([]);
  });

  it("names the package from an esbuild module comment inside a bundle", () => {
    const code = "(() => {\n  // src/app.js\n  var app = 1;\n\n  // node_modules/sneaky-analytics/dist/index.js\n" + ROTATOR + "\n})();";
    const f = obf(analyzeExt({ "manifest.json": mv3({ background: { service_worker: "bundle.js" } }), "bundle.js": code }));
    expect(f.length).toBe(1);
    expect(f[0].line).toBe(7); // the rotator IIFE
    expect(f[0].message).toContain("bundled package sneaky-analytics");
  });

  it("does not blame a package when the code follows a first-party module comment", () => {
    const code = "(() => {\n  // node_modules/react/index.js\n  var r = 1;\n  // src/app.js\n" + ROTATOR + "\n})();";
    const f = obf(analyzeExt({ "manifest.json": mv3({ background: { service_worker: "bundle.js" } }), "bundle.js": code }));
    expect(f.length).toBe(1);
    expect(f[0].message).not.toContain("bundled package");
    expect(f[0].fixHint).toContain("minified instead of obfuscated");
  });
});

describe("bundledPackageName", () => {
  it.each([
    ["vendor/x.js", "/*! acme-widget v2.4.1 | MIT */\nvar a;", null, "acme-widget@2.4.1"],
    ["node_modules/@scope/pkg/dist/index.js", "var a;", null, "@scope/pkg"],
    ["node_modules/a/node_modules/b/index.js", "var a;", null, "b"],
    ["vendor/obf-lib/index.js", "var a;", null, "obf-lib"],
    ["third_party/tracker.min.js", "var a;", null, "tracker"],
    ["js/app.js", "var a;", null, null],
    ["bundle.js", '/***/ "./node_modules/evil-lib/lib/x.js":\n/***/ (function(){var X})', 1, "evil-lib"],
    ["bundle.js", "// CONCATENATED MODULE: ./node_modules/foo/node_modules/bar/a.js\nvar X", 1, "bar"],
    ["bundle.js", "// CONCATENATED MODULE: ./src/a.js\nvar X", 1, null],
    ["bundle.js", "var x = 'node_modules/fake/'; var X", 1, null],
  ])("%s → %s", (rel, content, index, expected) => {
    // index = offset of the obfuscated code ("X") when one is given
    const at = index === null ? null : (content as string).lastIndexOf("X");
    expect(bundledPackageName(rel, content, at)).toBe(expected);
  });
});
