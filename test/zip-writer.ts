import { deflateRawSync } from "node:zlib";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Tiny zip WRITER for tests only (the product only reads). Produces standard
// zips: stored or deflate entries, UTF-8 flag, optional unix modes, optional
// CRX2/CRX3 header in front.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export interface ZipEntryInput {
  name: string;
  data?: string | Buffer | object;
  /** default: deflate */
  store?: boolean;
  /** unix mode, e.g. 0o120777 for a symlink */
  mode?: number;
}

export function buildZip(entries: ZipEntryInput[], opts: { crx?: 2 | 3; comment?: string } = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const raw = e.data === undefined ? Buffer.alloc(0)
      : Buffer.isBuffer(e.data) ? e.data
      : Buffer.from(typeof e.data === "string" ? e.data : JSON.stringify(e.data));
    const method = e.store ? 0 : 8;
    const comp = method === 8 ? deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name, "utf8");
    const crc = crc32(raw);
    const loc = Buffer.alloc(30);
    loc.writeUInt32LE(0x04034b50, 0);
    loc.writeUInt16LE(20, 4);
    loc.writeUInt16LE(0x800, 6);
    loc.writeUInt16LE(method, 8);
    loc.writeUInt32LE(crc, 14);
    loc.writeUInt32LE(comp.length, 18);
    loc.writeUInt32LE(raw.length, 22);
    loc.writeUInt16LE(name.length, 26);
    locals.push(loc, name, comp);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(e.mode !== undefined ? 0x031e : 20, 4); // made by unix when a mode is given
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0x800, 8);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(comp.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(((e.mode ?? 0) << 16) >>> 0, 38);
    cen.writeUInt32LE(offset, 42);
    centrals.push(cen, name);
    offset += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const comment = Buffer.from(opts.comment ?? "", "utf8");
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(comment.length, 20);
  const zip = Buffer.concat([...locals, cd, eocd, comment]);
  if (!opts.crx) return zip;
  if (opts.crx === 3) {
    const header = Buffer.from("fake-crx3-signed-header-proto-bytes");
    const pre = Buffer.alloc(12);
    pre.write("Cr24", 0, "latin1");
    pre.writeUInt32LE(3, 4);
    pre.writeUInt32LE(header.length, 8);
    return Buffer.concat([pre, header, zip]);
  }
  const key = Buffer.from("fake-public-key");
  const sig = Buffer.from("fake-signature-bytes");
  const pre = Buffer.alloc(16);
  pre.write("Cr24", 0, "latin1");
  pre.writeUInt32LE(2, 4);
  pre.writeUInt32LE(key.length, 8);
  pre.writeUInt32LE(sig.length, 12);
  return Buffer.concat([pre, key, sig, zip]);
}

/** Write an archive to a temp file, hand its path to fn, then delete it. */
export function withArchive<T>(buf: Buffer, ext: ".zip" | ".crx", fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "tsl-zip-"));
  try {
    const p = join(dir, `ext${ext}`);
    writeFileSync(p, buf);
    return fn(p);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
