import { openSync, readSync, closeSync, fstatSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { inflateRawSync } from "node:zlib";
import { ManifestError } from "./manifest.js";

// Minimal, dependency-free reader for the archives people upload to the Chrome
// Web Store: a .zip, or a .crx (CRX2/CRX3 header followed by a zip). Only the
// central directory, stored (0) and deflate (8) entries are supported; ZIP64,
// encrypted and multi-disk archives are refused with a clear error. Reads are
// random-access through a file descriptor, so a huge archive is never loaded
// into memory just to list it.

export type ArchiveKind = "zip" | "crx";

export interface ArchiveEntry {
  /** POSIX path inside the package (directories omitted) */
  relPath: string;
  /** uncompressed size in bytes, from the central directory */
  size: number;
  compressedSize: number;
  method: number;
  /** offset of the local file header, relative to the start of the file */
  localHeaderOffset: number;
  /** true when the entry is a symlink (unix mode in external attributes) */
  symlink: boolean;
}

export interface ArchiveListing {
  kind: ArchiveKind;
  /** size of the archive file on disk in bytes */
  fileSize: number;
  entries: ArchiveEntry[];
  /** entry names that were skipped because they escape the package root */
  unsafePaths: string[];
}

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

export function isArchivePath(p: string): boolean {
  return /\.(zip|crx)$/i.test(p);
}

function readAt(fd: number, pos: number, len: number): Buffer {
  const buf = Buffer.alloc(len);
  let off = 0;
  while (off < len) {
    const n = readSync(fd, buf, off, len - off, pos + off);
    if (n === 0) break;
    off += n;
  }
  return off === len ? buf : buf.subarray(0, off);
}

/** Normalize an entry name to a safe POSIX relative path, or null when it would
 *  escape the package (absolute, drive-letter, or ".." segments). */
export function safeEntryPath(name: string): string | null {
  const p = name.replace(/\\/g, "/");
  if (p.startsWith("/") || /^[a-zA-Z]:/.test(p)) return null;
  const parts: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") return null;
    parts.push(seg);
  }
  return parts.length ? parts.join("/") : null;
}

/** Byte length of a CRX header (0 for a plain zip). Throws on a bad CRX. */
function crxHeaderLength(fd: number, fileSize: number): { kind: ArchiveKind; skip: number } {
  const head = readAt(fd, 0, Math.min(16, fileSize));
  if (head.length < 4 || head.toString("latin1", 0, 4) !== "Cr24") return { kind: "zip", skip: 0 };
  if (head.length < 12) throw new ManifestError("Truncated CRX header");
  const version = head.readUInt32LE(4);
  if (version === 3) return { kind: "crx", skip: 12 + head.readUInt32LE(8) };
  if (version === 2) {
    if (head.length < 16) throw new ManifestError("Truncated CRX2 header");
    return { kind: "crx", skip: 16 + head.readUInt32LE(8) + head.readUInt32LE(12) };
  }
  throw new ManifestError(`Unsupported CRX version ${version}`);
}

/** List the entries of a .zip/.crx without extracting anything. */
export function listArchive(path: string): ArchiveListing {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (e) {
    throw new ManifestError(`Could not open archive: ${(e as Error).message}`);
  }
  try {
    return listFd(fd);
  } finally {
    closeSync(fd);
  }
}

function listFd(fd: number): ArchiveListing {
  const fileSize = fstatSync(fd).size;
  const { kind, skip } = crxHeaderLength(fd, fileSize);
  if (skip > fileSize) throw new ManifestError("CRX header is larger than the file");

  // End of central directory: last 22 bytes + up to 64 KiB comment.
  const tailLen = Math.min(fileSize - skip, 22 + 0xffff);
  if (tailLen < 22) throw new ManifestError("Not a zip archive (too small)");
  const tailStart = fileSize - tailLen;
  const tail = readAt(fd, tailStart, tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === EOCD_SIG) { eocd = i; break; }
  }
  if (eocd < 0) throw new ManifestError("Not a zip archive (no end-of-central-directory record)");
  const disk = tail.readUInt16LE(eocd + 4);
  const total = tail.readUInt16LE(eocd + 10);
  const cdSize = tail.readUInt32LE(eocd + 12);
  const cdOffset = tail.readUInt32LE(eocd + 16);
  if (disk !== 0) throw new ManifestError("Multi-disk zip archives are not supported");
  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ManifestError("ZIP64 archives are not supported");
  }
  const eocdPos = tailStart + eocd;
  // Tolerate data prepended to the zip (CRX header, self-extractor stubs):
  // central-directory offsets are relative to where the zip itself starts.
  const base = eocdPos - cdSize - cdOffset;
  if (base < 0 || eocdPos - cdSize < skip) throw new ManifestError("Corrupt zip archive (bad central directory offset)");

  const cd = readAt(fd, base + cdOffset, cdSize);
  const entries = new Map<string, ArchiveEntry>();
  const unsafePaths: string[] = [];
  let p = 0;
  for (let n = 0; n < total; n++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== CEN_SIG) throw new ManifestError("Corrupt zip archive (bad central directory entry)");
    const flags = cd.readUInt16LE(p + 8);
    const method = cd.readUInt16LE(p + 10);
    const compressedSize = cd.readUInt32LE(p + 20);
    const size = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    const externalAttrs = cd.readUInt32LE(p + 38);
    const localOffset = cd.readUInt32LE(p + 42);
    const rawName = cd.subarray(p + 46, p + 46 + nameLen);
    // bit 11 = UTF-8 names; otherwise CP437, which matches ASCII for real-world names.
    const name = rawName.toString(flags & 0x800 ? "utf8" : "latin1");
    p += 46 + nameLen + extraLen + commentLen;
    if (flags & 0x1) throw new ManifestError(`Encrypted zip entries are not supported (${name})`);
    if (size === 0xffffffff || compressedSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new ManifestError("ZIP64 archives are not supported");
    }
    if (name.endsWith("/") || name.endsWith("\\")) continue; // directory entry
    const rel = safeEntryPath(name);
    if (rel === null) { unsafePaths.push(name); continue; }
    const mode = externalAttrs >>> 16;
    entries.set(rel, {
      relPath: rel,
      size,
      compressedSize,
      method,
      localHeaderOffset: base + localOffset,
      symlink: (mode & 0o170000) === 0o120000,
    });
  }
  return { kind, fileSize, entries: [...entries.values()], unsafePaths };
}

function readEntryData(fd: number, e: ArchiveEntry): Buffer {
  const loc = readAt(fd, e.localHeaderOffset, 30);
  if (loc.length < 30 || loc.readUInt32LE(0) !== LOC_SIG) throw new ManifestError(`Corrupt zip archive (bad local header for ${e.relPath})`);
  const dataStart = e.localHeaderOffset + 30 + loc.readUInt16LE(26) + loc.readUInt16LE(28);
  const raw = readAt(fd, dataStart, e.compressedSize);
  if (raw.length !== e.compressedSize) throw new ManifestError(`Corrupt zip archive (truncated data for ${e.relPath})`);
  if (e.method === 0) return raw;
  if (e.method === 8) {
    try {
      return inflateRawSync(raw, { maxOutputLength: Math.max(e.size, 1) });
    } catch (err) {
      throw new ManifestError(`Could not inflate ${e.relPath}: ${(err as Error).message}`);
    }
  }
  throw new ManifestError(`Unsupported zip compression method ${e.method} (${e.relPath})`);
}

/** Files whose CONTENT the engine reads; everything else (images, fonts, wasm…)
 *  is materialized as an empty placeholder so existence checks still work. */
const CONTENT_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|html?|json)$/i;
/** Per-file and total caps on extracted content, a guard against zip bombs. */
export const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

export interface ExtractedArchive {
  listing: ArchiveListing;
  /** temp directory holding the package; remove with cleanup() */
  dir: string;
  cleanup: () => void;
}

/** Extract a .zip/.crx into a fresh temp directory for analysis. Never follows
 *  or creates symlinks, never writes outside the temp dir. */
export function extractArchive(path: string): ExtractedArchive {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (e) {
    throw new ManifestError(`Could not open archive: ${(e as Error).message}`);
  }
  const dir = mkdtempSync(join(tmpdir(), "tabsmith-pkg-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  try {
    const listing = listFd(fd);
    const dirs = new Set(listing.entries.flatMap((e) => {
      const parts = e.relPath.split("/");
      return parts.slice(1).map((_, i) => parts.slice(0, i + 1).join("/"));
    }));
    let total = 0;
    for (const e of listing.entries) {
      if (dirs.has(e.relPath)) continue; // file/dir name clash: keep the directory
      const abs = join(dir, ...e.relPath.split("/"));
      mkdirSync(dirname(abs), { recursive: true });
      let data: Buffer = Buffer.alloc(0);
      if (!e.symlink && CONTENT_EXT.test(e.relPath) && e.size <= MAX_ENTRY_BYTES) {
        total += e.size;
        if (total > MAX_TOTAL_BYTES) throw new ManifestError("Archive expands to more than 512 MiB of code/JSON; refusing to extract");
        data = readEntryData(fd, e);
      }
      writeFileSync(abs, data);
    }
    return { listing, dir, cleanup };
  } catch (e) {
    cleanup();
    throw e;
  } finally {
    closeSync(fd);
  }
}
