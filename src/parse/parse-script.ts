import { parse, type ParserPlugin } from "@babel/parser";
import type { VirtualFile, ScriptFile } from "../engine/model.js";

// ponytail: @babel/parser is the committed parser. oxc-parser was the planned
// primary but is a native binding with a churny API, and its only v0.1 edge
// (perf on large/minified files) is explicitly out of scope. The parseScript()
// seam below is the single point where oxc could later slot in.

function pluginsFor(relPath: string): ParserPlugin[] {
  const lower = relPath.toLowerCase();
  if (lower.endsWith(".tsx")) return ["typescript", "jsx"];
  if (lower.endsWith(".ts")) return ["typescript"];
  return ["jsx"]; // .js/.mjs/.cjs/.jsx
}

/** Parse one file behind the seam. Never throws — a parse failure yields a
 *  ScriptFile with ast=null and parseError=true so other files still process. */
export function parseScript(file: VirtualFile): ScriptFile {
  try {
    const ast = parse(file.content, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      errorRecovery: true,
      plugins: pluginsFor(file.relPath),
    });
    return { ...file, ast, parseError: false };
  } catch {
    return { ...file, ast: null, parseError: true };
  }
}

/** Depth-first walk over a babel AST. Calls visitor(node) for every node that
 *  carries a string `type`. Lazy generic traversal — no @babel/traverse, no scope. */
export function walk(node: any, visitor: (node: any) => void): void {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") visitor(node);
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "leadingComments" || key === "trailingComments") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) walk(c, visitor);
    } else if (child && typeof child === "object" && typeof child.type === "string") {
      walk(child, visitor);
    }
  }
}
