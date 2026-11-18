// Node-side helper: builds a VEIL PNG in memory using the same pieces as the Worker.
import { CHUNK_DATA, CHUNK_HEADER, CHUNK_TRAILER, createEncryptor, pngChunk, splitCarrier } from '../src/veil.js';

export async function buildPng(carrier, data, { pass, name = 'file.bin', mime = 'application/octet-stream', feed = 65536, ...opts }) {
  const { head, tail } = splitCarrier(carrier);
  const enc = await createEncryptor({ pass, name, mime, ...opts });
  const parts = [head, pngChunk(CHUNK_HEADER, enc.header)];
  for (let o = 0; o < data.length; o += feed) {
    for (const b of await enc.write(data.subarray(o, o + feed))) parts.push(pngChunk(CHUNK_DATA, b));
  }
  const { blocks, trailer } = await enc.finish();
  for (const b of blocks) parts.push(pngChunk(CHUNK_DATA, b));
  parts.push(pngChunk(CHUNK_TRAILER, trailer), tail);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
