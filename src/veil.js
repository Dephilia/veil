// veil.js — single source of truth for the VEIL container format.
//
// Environment-agnostic on purpose: only globalThis.crypto.subtle, TextEncoder,
// TextDecoder, Uint8Array/DataView are used. The same file runs in the Worker,
// in browsers (inlined into public/decrypt.html by tools/build-standalone.mjs)
// and in Node. Keep it free of imports, Node APIs and Worker-only APIs.
//
// A VEIL PNG carries its payload in private ancillary chunks placed after the
// last IDAT, so no total length has to be known before streaming starts:
//
//   tOMh  header  (40 bytes, layout below)
//   tOMd  one per block: u32 index || AES-256-GCM(block) + 16-byte tag
//   tOMt  trailer: blockCount(u32) | plainLen(u64) | rootHash(SHA-256 of plaintext)
//
// Header v3:
//   0 magic "VEIL" | 4 version(3) | 5 kdfId(1=pbkdf2-sha256-chained) | 6 stages(u8)
//   7 reserved(0)  | 8 salt(16, stage-0 salt) | 24 itersPerStage(u32)
//   28 blockSize(u32) | 32 nonceTag(8)
//
// Per-block nonce = nonceTag(8) || u32 index, AAD = "VEIL" || u32 index, so a
// chunk moved into another slot fails authentication. Truncation or block
// removal is caught by the trailer count and by rootHash.
//
// Framed plaintext = u32 jsonLen | JSON {"name","mime"} | file bytes.
//
// KDF: production workerd rejects PBKDF2 above 100000 iterations, so the key is
// a chain of native PBKDF2-SHA256 calls, each salted with the previous output:
//   s = salt; repeat STAGES times: out = PBKDF2(pass, s, itersPerStage, 32); s = out
//   key = out

export const MAGIC = 'VEIL';
export const VERSION = 3;
export const KDF_PBKDF2_CHAINED = 1;
export const CHUNK_HEADER = 'tOMh';
export const CHUNK_DATA = 'tOMd';
export const CHUNK_TRAILER = 'tOMt';
export const STAGES = 6;
export const ITERS_PER_STAGE = 100000;
export const MAX_ITERS_PER_STAGE = 100000; // platform ceiling
export const MAX_STAGES = 32;
export const MAX_TOTAL_ITERS = 6000000;
export const BLOCK_SIZE = 1048576;
export const MAX_PAYLOAD = 100 * 1024 * 1024;
export const HEADER_LEN = 40;
export const TRAILER_LEN = 44;
export const TAG_LEN = 16;
export const HASH_LEN = 32;
export const MAX_BLOCK_SIZE = 1 << 28;

export class VeilError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VeilError';
  }
}

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

// ---------------------------------------------------------------- SHA-256
// WebCrypto has no incremental digest and rootHash must be computed while
// streaming, so a small incremental implementation lives here.

const SHA_K = new Uint32Array(64);
const SHA_H = new Uint32Array(8);
(() => {
  const primes = [];
  for (let n = 2; primes.length < 64; n++) {
    if (primes.every((p) => n % p)) primes.push(n);
  }
  const frac = (x) => Math.floor((x - Math.floor(x)) * 4294967296);
  for (let i = 0; i < 64; i++) SHA_K[i] = frac(Math.cbrt(primes[i]));
  for (let i = 0; i < 8; i++) SHA_H[i] = frac(Math.sqrt(primes[i]));
})();

export class Sha256 {
  constructor() {
    this.h = Uint32Array.from(SHA_H);
    this.buf = new Uint8Array(64);
    this.w = new Uint32Array(64);
    this.n = 0;
    this.total = 0;
  }

  update(data) {
    const len = data.length;
    let i = 0;
    this.total += len;
    if (this.n) {
      const take = Math.min(64 - this.n, len);
      this.buf.set(data.subarray(0, take), this.n);
      this.n += take;
      i = take;
      if (this.n === 64) {
        this._block(this.buf, 0);
        this.n = 0;
      }
    }
    for (; i + 64 <= len; i += 64) this._block(data, i);
    if (i < len) {
      this.buf.set(data.subarray(i), 0);
      this.n = len - i;
    }
    return this;
  }

  _block(b, o) {
    const w = this.w;
    const h = this.h;
    const K = SHA_K;
    for (let t = 0; t < 16; t++, o += 4) {
      w[t] = (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
    }
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15];
      const y = w[t - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    let a = h[0], b2 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b2) ^ (a & c) ^ (b2 & c);
      const t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b2; b2 = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += b2; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  digest() {
    const bits = this.total * 8;
    const pad = new Uint8Array((this.n < 56 ? 64 : 128) - this.n);
    pad[0] = 0x80;
    const dv = new DataView(pad.buffer);
    dv.setUint32(pad.length - 8, Math.floor(bits / 4294967296));
    dv.setUint32(pad.length - 4, bits >>> 0);
    this.update(pad);
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, this.h[i]);
    return out;
  }
}

// ---------------------------------------------------------------- CRC-32

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c >>> 0;
}

export class Crc32 {
  constructor() {
    this.c = 0xffffffff;
  }
  update(data) {
    let c = this.c;
    for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
    this.c = c;
    return this;
  }
  value() {
    return (this.c ^ 0xffffffff) >>> 0;
  }
}

// ---------------------------------------------------------------- PNG chunks

export const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function typeAt(b, o) {
  return String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);
}

// Walks the chunk list. Yields {type, start, dataStart, length, end}; `start` is
// the offset of the length field, `end` is just past the CRC.
export function* walkChunks(bytes, { verifyCrc = false } = {}) {
  if (bytes.length < 8) throw new VeilError('not a PNG file');
  for (let i = 0; i < 8; i++) if (bytes[i] !== PNG_SIGNATURE[i]) throw new VeilError('not a PNG file (bad signature)');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = 8;
  while (pos < bytes.length) {
    if (pos + 12 > bytes.length) throw new VeilError('PNG is truncated (partial chunk header)');
    const length = dv.getUint32(pos);
    const type = typeAt(bytes, pos + 4);
    const end = pos + 12 + length;
    if (end > bytes.length) throw new VeilError(`PNG is truncated (chunk ${type} runs past end of file)`);
    if (verifyCrc) {
      const crc = new Crc32().update(bytes.subarray(pos + 4, pos + 8 + length)).value();
      if (crc !== dv.getUint32(end - 4)) throw new VeilError(`bad CRC in PNG chunk ${type}`);
    }
    yield { type, start: pos, dataStart: pos + 8, length, end };
    pos = end;
    if (type === 'IEND') break;
  }
}

// Builds one complete PNG chunk: length | type | data | crc32(type||data).
export function pngChunk(type, data) {
  if (typeof type !== 'string' || type.length !== 4) throw new VeilError('chunk type must be 4 characters');
  const typeBytes = te.encode(type);
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  out.set(typeBytes, 4);
  out.set(data, 8);
  dv.setUint32(8 + data.length, new Crc32().update(typeBytes).update(data).value());
  return out;
}

// Splits a carrier PNG into head (signature .. end of last IDAT) and tail.
export function splitCarrier(bytes) {
  let lastIdatEnd = -1;
  let sawIend = false;
  for (const c of walkChunks(bytes)) {
    if (c.type === 'IDAT') lastIdatEnd = c.end;
    if (c.type === 'IEND') sawIend = true;
  }
  if (lastIdatEnd < 0) throw new VeilError('carrier PNG has no IDAT chunk');
  if (!sawIend) throw new VeilError('carrier PNG has no IEND chunk');
  return { head: bytes.subarray(0, lastIdatEnd), tail: bytes.subarray(lastIdatEnd) };
}

// ---------------------------------------------------------------- crypto

// Chained PBKDF2-SHA256; returns the raw 32-byte key.
export async function deriveKeyBytes(pass, salt, stages = STAGES, itersPerStage = ITERS_PER_STAGE) {
  const base = await subtle().importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
  let s = salt;
  for (let k = 0; k < stages; k++) {
    const bits = await subtle().deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: s, iterations: itersPerStage },
      base,
      256,
    );
    s = new Uint8Array(bits);
  }
  return s;
}

export async function deriveKey(pass, salt, stages = STAGES, itersPerStage = ITERS_PER_STAGE) {
  const raw = await deriveKeyBytes(pass, salt, stages, itersPerStage);
  return subtle().importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function blockNonce(nonceTag, i) {
  const n = new Uint8Array(12);
  n.set(nonceTag, 0);
  new DataView(n.buffer).setUint32(8, i);
  return n;
}

function blockAad(i) {
  const a = new Uint8Array(8);
  a.set(te.encode(MAGIC), 0);
  new DataView(a.buffer).setUint32(4, i);
  return a;
}

function framePrefix(name, mime) {
  const json = te.encode(JSON.stringify({ name, mime }));
  const out = new Uint8Array(4 + json.length);
  new DataView(out.buffer).setUint32(0, json.length);
  out.set(json, 4);
  return out;
}

export function blockCountFor(plainLen, blockSize) {
  return Math.ceil(plainLen / blockSize);
}

// Streaming encryptor. Usage:
//   const enc = await createEncryptor({pass, name, mime});
//   emit pngChunk(CHUNK_HEADER, enc.header)
//   for (b of await enc.write(piece)) emit pngChunk(CHUNK_DATA, b)
//   const { blocks, trailer } = await enc.finish()
//   for (b of blocks) emit pngChunk(CHUNK_DATA, b); emit pngChunk(CHUNK_TRAILER, trailer)
export async function createEncryptor({
  pass,
  name,
  mime,
  blockSize = BLOCK_SIZE,
  itersPerStage = ITERS_PER_STAGE,
  stages = STAGES,
  maxBytes = MAX_PAYLOAD,
}) {
  const prefix = framePrefix(name, mime);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const nonceTag = globalThis.crypto.getRandomValues(new Uint8Array(8));
  const key = await deriveKey(pass, salt, stages, itersPerStage);

  const header = new Uint8Array(HEADER_LEN);
  const hv = new DataView(header.buffer);
  header.set(te.encode(MAGIC), 0);
  header[4] = VERSION;
  header[5] = KDF_PBKDF2_CHAINED;
  header[6] = stages;
  header.set(salt, 8);
  hv.setUint32(24, itersPerStage);
  hv.setUint32(28, blockSize);
  header.set(nonceTag, 32);

  const sha = new Sha256();
  const buf = new Uint8Array(blockSize);
  let fill = 0;
  let fed = 0;
  let index = 0;
  let finished = false;

  async function sealBlock(len) {
    const plain = buf.subarray(0, len);
    sha.update(plain);
    const ct = new Uint8Array(
      await subtle().encrypt(
        { name: 'AES-GCM', iv: blockNonce(nonceTag, index), additionalData: blockAad(index), tagLength: 128 },
        key,
        plain,
      ),
    );
    const payload = new Uint8Array(4 + ct.length);
    new DataView(payload.buffer).setUint32(0, index);
    payload.set(ct, 4);
    index++;
    return payload;
  }

  async function feed(data, out) {
    fed += data.length;
    if (fed - prefix.length > maxBytes) throw new VeilError(`payload exceeds ${maxBytes} bytes`);
    let off = 0;
    while (off < data.length) {
      const take = Math.min(blockSize - fill, data.length - off);
      buf.set(data.subarray(off, off + take), fill);
      fill += take;
      off += take;
      if (fill === blockSize) {
        out.push(await sealBlock(blockSize));
        fill = 0;
      }
    }
  }

  let prefixPending = true;
  return {
    header,
    blockSize,
    async write(data) {
      if (finished) throw new VeilError('encryptor already finished');
      const out = [];
      if (prefixPending) {
        prefixPending = false;
        await feed(prefix, out);
      }
      await feed(data, out);
      return out;
    },
    async finish() {
      if (finished) throw new VeilError('encryptor already finished');
      finished = true;
      const blocks = [];
      if (prefixPending) {
        prefixPending = false;
        await feed(prefix, blocks);
      }
      if (fill > 0) blocks.push(await sealBlock(fill));
      const trailer = new Uint8Array(TRAILER_LEN);
      const tv = new DataView(trailer.buffer);
      tv.setUint32(0, index);
      tv.setBigUint64(4, BigInt(fed));
      trailer.set(sha.digest(), 12);
      return { blocks, trailer };
    },
  };
}

function hex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

// Collects the VEIL chunks of a PNG held in memory. Returns null when the file
// carries no VEIL chunks at all.
export function openVeil(bytes) {
  let header = null;
  let trailer = null;
  const blocks = [];
  for (const c of walkChunks(bytes)) {
    const data = bytes.subarray(c.dataStart, c.dataStart + c.length);
    if (c.type === CHUNK_HEADER && header === null) header = data;
    else if (c.type === CHUNK_DATA) blocks.push(data);
    else if (c.type === CHUNK_TRAILER && trailer === null) trailer = data;
  }
  if (!header && !blocks.length && !trailer) return null;
  if (!header) throw new VeilError('VEIL header chunk is missing');
  if (!trailer) throw new VeilError('VEIL trailer chunk is missing (file truncated?)');
  return { header, blocks, trailer };
}

// Decrypts one opened container. Returns {name, mime, size, bytes, rootHash}.
export async function decryptContainer({ header, blocks, trailer }, pass, { onProgress, onStage } = {}) {
  if (!header || header.length !== HEADER_LEN) throw new VeilError('VEIL header is the wrong size');
  if (!trailer || trailer.length !== TRAILER_LEN) throw new VeilError('VEIL trailer is the wrong size');
  const hv = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (td.decode(header.subarray(0, 4)) !== MAGIC) throw new VeilError('not a VEIL container (bad magic)');
  if (header[4] !== VERSION) throw new VeilError(`unsupported VEIL version ${header[4]}`);
  if (header[5] !== KDF_PBKDF2_CHAINED) throw new VeilError(`unsupported KDF id ${header[5]}`);
  const stages = header[6];
  const salt = header.subarray(8, 24);
  const itersPerStage = hv.getUint32(24);
  const blockSize = hv.getUint32(28);
  const nonceTag = header.subarray(32, 40);
  if (stages < 1 || stages > MAX_STAGES) throw new VeilError(`implausible KDF stage count ${stages}`);
  if (itersPerStage < 1 || itersPerStage > MAX_ITERS_PER_STAGE) {
    throw new VeilError(`implausible PBKDF2 iterations per stage ${itersPerStage}`);
  }
  if (stages * itersPerStage > MAX_TOTAL_ITERS) throw new VeilError('implausible total KDF cost');
  if (blockSize < 1 || blockSize > MAX_BLOCK_SIZE) throw new VeilError(`implausible block size ${blockSize}`);

  const tv = new DataView(trailer.buffer, trailer.byteOffset, trailer.byteLength);
  const blockCount = tv.getUint32(0);
  const plainBig = tv.getBigUint64(4);
  if (plainBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new VeilError('implausible plaintext length');
  const plainLen = Number(plainBig);
  if (plainLen < 6) throw new VeilError('implausible plaintext length');
  if (blockCount !== blockCountFor(plainLen, blockSize)) {
    throw new VeilError('trailer block count does not match plaintext length');
  }
  if (blocks.length !== blockCount) {
    throw new VeilError(`expected ${blockCount} data chunks, found ${blocks.length}`);
  }

  if (onStage) onStage('kdf');
  const key = await deriveKey(pass, salt, stages, itersPerStage);
  if (onStage) onStage('decrypt');

  const plain = new Uint8Array(plainLen);
  const sha = new Sha256();
  for (let i = 0; i < blockCount; i++) {
    const chunk = blocks[i];
    const len = Math.min(blockSize, plainLen - i * blockSize);
    if (chunk.length !== 4 + len + TAG_LEN) throw new VeilError(`block ${i + 1} has the wrong size`);
    const ci = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getUint32(0);
    if (ci !== i) throw new VeilError(`block ${i + 1} is out of order (carries index ${ci})`);
    let pt;
    try {
      pt = await subtle().decrypt(
        { name: 'AES-GCM', iv: blockNonce(nonceTag, i), additionalData: blockAad(i), tagLength: 128 },
        key,
        chunk.subarray(4),
      );
    } catch {
      throw new VeilError(
        i === 0
          ? 'authentication failed: wrong passphrase, or the file is corrupted'
          : `authentication failed at block ${i + 1} of ${blockCount}: the data was modified or corrupted`,
      );
    }
    const view = new Uint8Array(pt);
    plain.set(view, i * blockSize);
    sha.update(view);
    if (onProgress) onProgress(i + 1, blockCount);
  }

  const got = sha.digest();
  const want = trailer.subarray(12, 12 + HASH_LEN);
  for (let i = 0; i < HASH_LEN; i++) {
    if (want[i] !== got[i]) throw new VeilError('root hash mismatch: decrypted data does not match the stored hash');
  }

  const jsonLen = new DataView(plain.buffer).getUint32(0);
  if (4 + jsonLen > plainLen) throw new VeilError('malformed metadata frame');
  let meta;
  try {
    meta = JSON.parse(td.decode(plain.subarray(4, 4 + jsonLen)));
  } catch {
    throw new VeilError('malformed metadata JSON');
  }
  const bytes = plain.subarray(4 + jsonLen);
  return {
    name: typeof meta.name === 'string' ? meta.name : 'file',
    mime: typeof meta.mime === 'string' ? meta.mime : 'application/octet-stream',
    size: bytes.length,
    bytes,
    rootHash: hex(got),
  };
}
