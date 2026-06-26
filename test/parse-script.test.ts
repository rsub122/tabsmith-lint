import { describe, it, expect } from "vitest";
import { script } from "./helpers.js";

describe("U4: parseScript seam", () => {
  it("parses a .ts file", () => {
    const s = script("const x: number = chrome.storage ? 1 : 2;", "a.ts");
    expect(s.parseError).toBe(false);
    expect(s.ast).not.toBeNull();
  });

  it("parses a .tsx file", () => {
    const s = script("const el = <div>{chrome.runtime.id}</div>;", "a.tsx");
    expect(s.parseError).toBe(false);
  });

  it("a broken file → parseError, no throw, ast null", () => {
    const s = script("function ( { this is not js", "broken.js");
    expect(s.parseError).toBe(true);
    expect(s.ast).toBeNull();
  });

  it("returned nodes carry line/column", () => {
    const s = script("\nchrome.storage.local.get();", "a.js");
    const call = s.ast.program.body[0].expression;
    expect(call.loc.start.line).toBe(2);
    expect(typeof call.loc.start.column).toBe("number");
  });
});
