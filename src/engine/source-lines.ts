// ponytail: naive first-match line lookup. Manifest findings get an approximate
// line by searching the raw JSON text for a needle. Good enough for a hint;
// upgrade to a real JSON AST (jsonc-parser) only if precise locations are needed.

export function findLine(source: string, needle: string): number | undefined {
  if (!needle) return undefined;
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle)) return i + 1;
  }
  return undefined;
}

/** 1-based line number for a character offset into `source`. */
export function findLineByIndex(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

/** Strip a leading UTF-8 BOM (U+FEFF). Windows/PowerShell-authored files often
 *  carry one, which would otherwise break JSON.parse and source scanning. */
export function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}
