import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  BLOCK_SIZE, HEADER_LEN, TRAILER_LEN, Sha256, Crc32, walkChunks, openVeil, decryptContainer, VeilError,
  CHUNK_HEADER, CHUNK_DATA, CHUNK_TRAILER,
} from '../src/veil.js';
import { buildPng } from '../tools/chunk.mjs';
import { inlineSource } from '../tools/build-standalone.mjs';
import { loadInlined } from '../tools/extract-inlined.mjs';

const carrier = new Uint8Array(readFileSync(new URL('../public/carrier.png', import.meta.url)));
const PASS = 'correct horse battery staple';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const rnd = (n) => new Uint8Array(randomBytes(n));
const tmp = mkdtempSync(join(tmpdir(), 'veil-test-'));
test.after(() => rmSync(tmp, { recursive: true, force: true }));

test('Sha256 matches node crypto across lengths and split updates', () => {
  for (const n of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 100003]) {
    const d = rnd(n);
    const h = new Sha256();
    const cut = Math.floor(n / 3);
    h.update(d.subarray(0, cut)).update(d.subarray(cut));
    assert.equal(Buffer.from(h.digest()).toString('hex'), sha(d), `len ${n}`);
  }
});

test('Crc32 matches the known check value', () => {
  assert.equal(new Crc32().update(new TextEncoder().encode('123456789')).value(), 0xcbf43926);
});

const sizes = [
  ['0 B', 0], ['1 B', 1], ['blockSize-1', BLOCK_SIZE - 1], ['blockSize', BLOCK_SIZE],
  ['blockSize+1', BLOCK_SIZE + 1], ['3*blockSize+7', 3 * BLOCK_SIZE + 7], ['100 MB-1', 100 * 1024 * 1024 - 1],
];
for (const [label, n] of sizes) {
  test(`round-trip ${label} (${n} bytes)`, { timeout: 300000 }, async () => {
    const data = rnd(n);
    const t0 = performance.now();
    const png = await buildPng(carrier, data, { pass: PASS, name: 'x.bin', mime: 'application/x-test' });
    const t1 = performance.now();
    const r = await decryptContainer(openVeil(png), PASS);
    const t2 = performance.now();
    assert.equal(r.size, n);
    assert.equal(sha(r.bytes), sha(data));
    assert.equal(r.name, 'x.bin');
    assert.equal(r.mime, 'application/x-test');
    assert.equal(r.rootHash.length, 64);
    // rootHash covers the whole framed plaintext: recompute independently
    const json = Buffer.from(JSON.stringify({ name: 'x.bin', mime: 'application/x-test' }));
    const len = Buffer.alloc(4); len.writeUInt32BE(json.length);
    assert.equal(r.rootHash, sha(Buffer.concat([len, json, data])));
    console.log(`    ${label}: png=${png.length} B  encrypt=${(t1 - t0).toFixed(0)} ms  decrypt=${(t2 - t1).toFixed(0)} ms`);
  });
}

test('wrong passphrase throws a clear message', async () => {
  const png = await buildPng(carrier, rnd(1000), { pass: PASS });
  await assert.rejects(decryptContainer(openVeil(png), 'nope'), (e) => e instanceof VeilError && /wrong passphrase/.test(e.message));
});

test('flipped byte in one block -> authentication failure naming the block', async () => {
  const data = rnd(3 * BLOCK_SIZE + 7);
  const png = await buildPng(carrier, data, { pass: PASS });
  const c = openVeil(png);
  const blocks = c.blocks.map((b) => Uint8Array.from(b));
  blocks[1][500] ^= 0x01;
  await assert.rejects(
    decryptContainer({ ...c, blocks }, PASS),
    (e) => e instanceof VeilError && /authentication failed at block 2 of 4/.test(e.message),
  );
});

test('dropped last block -> failure', async () => {
  const data = rnd(2 * BLOCK_SIZE + 100);
  const png = await buildPng(carrier, data, { pass: PASS });
  const c = openVeil(png);
  await assert.rejects(
    decryptContainer({ ...c, blocks: c.blocks.slice(0, -1) }, PASS),
    (e) => e instanceof VeilError && /expected 3 data chunks, found 2/.test(e.message),
  );
});

test('reordered blocks -> rejected before decrypting', async () => {
  const data = rnd(3 * BLOCK_SIZE + 7);
  const png = await buildPng(carrier, data, { pass: PASS });
  const c = openVeil(png);
  const blocks = c.blocks.slice();
  [blocks[0], blocks[2]] = [blocks[2], blocks[0]];
  await assert.rejects(
    decryptContainer({ ...c, blocks }, PASS),
    (e) => e instanceof VeilError && /out of order/.test(e.message),
  );
});

test('produced PNG parses: valid chunk list + CRCs, VEIL chunks after the last IDAT', async () => {
  const png = await buildPng(carrier, rnd(2_500_000), { pass: PASS });
  const chunks = [...walkChunks(png, { verifyCrc: true })];
  const types = chunks.map((c) => c.type);
  assert.equal(types[0], 'IHDR');
  assert.equal(types.at(-1), 'IEND');
  const lastIdat = types.lastIndexOf('IDAT');
  assert.equal(types[lastIdat + 1], CHUNK_HEADER);
  assert.equal(types.filter((t) => t === CHUNK_HEADER).length, 1);
  assert.equal(types.filter((t) => t === CHUNK_TRAILER).length, 1);
  assert.equal(types.at(-2), CHUNK_TRAILER, 'trailer sits just before IEND');
  assert.ok(types.filter((t) => t === CHUNK_DATA).length >= 2);
  assert.equal(chunks.at(-1).end, png.length, 'no trailing garbage');
  const orig = [...walkChunks(carrier)].map((c) => c.type);
  assert.deepEqual(types.filter((t) => ![CHUNK_HEADER, CHUNK_DATA, CHUNK_TRAILER].includes(t)), orig);
});

test('image still decodes (PIL)', async () => {
  const png = await buildPng(carrier, rnd(3_000_000), { pass: PASS });
  const f = join(tmp, 'probe.png');
  writeFileSync(f, png);
  const probe = (p) => JSON.parse(execFileSync('python3', ['-I', new URL('./png_probe.py', import.meta.url).pathname, p]).toString());
  const orig = probe(new URL('../public/carrier.png', import.meta.url).pathname);
  const got = probe(f);
  assert.deepEqual(got.size, orig.size);
  assert.equal(got.mode, orig.mode);
  assert.equal(got.format, 'PNG');
  console.log(`    PIL: size=${got.size} mode=${got.mode}`);
});

test('tolerates an extra ancillary chunk and a moved VEIL block group', async () => {
  const data = rnd(5000);
  const png = await buildPng(carrier, data, { pass: PASS });
  const chunks = [...walkChunks(png)];
  const first = chunks.find((c) => c.type === CHUNK_HEADER);
  const veil = png.subarray(first.start);
  const without = png.subarray(0, first.start);
  const ihdrEnd = chunks[0].end;
  const junk = Buffer.alloc(12);
  junk.writeUInt32BE(0, 0);
  junk.write('teXt', 4);
  junk.writeUInt32BE(new Crc32().update(junk.subarray(4, 8)).value(), 8);
  // move the whole VEIL block right after IHDR, and drop a junk chunk before it
  const moved = new Uint8Array(Buffer.concat([
    without.subarray(0, ihdrEnd), junk, veil,
  ]));
  const r = await decryptContainer(openVeil(moved), PASS);
  assert.equal(sha(r.bytes), sha(data));
});

test('decrypt.html inlined crypto is current and decrypts', async () => {
  const html = readFileSync(new URL('../public/decrypt.html', import.meta.url), 'utf8');
  assert.ok(html.includes(inlineSource()), 'run `npm run build:pages` — decrypt.html is stale');
  assert.ok(!/https?:\/\//.test(html.replace(/<script[\s\S]*?<\/script>/g, '')), 'no external URLs in markup');
  const data = rnd(2 * BLOCK_SIZE + 3);
  const png = await buildPng(carrier, data, { pass: PASS });
  const { decryptContainer: d, openVeil: o } = loadInlined();
  const r = await d(o(png), PASS);
  assert.equal(sha(r.bytes), sha(data));
});

test('header v3 layout and validation rejects bad KDF fields', async () => {
  const png = await buildPng(carrier, rnd(100), { pass: PASS });
  const c = openVeil(png);
  const p = c.header;
  assert.equal(HEADER_LEN, 40);
  assert.equal(TRAILER_LEN, 44);
  assert.deepEqual([p[4], p[5], p[6], p[7]], [3, 1, 6, 0]);
  assert.equal(Buffer.from(p).readUInt32BE(24), 100000);
  const bad = async (mut, re) => {
    const q = Buffer.from(p); mut(q);
    await assert.rejects(decryptContainer({ ...c, header: new Uint8Array(q) }, PASS), (e) => e instanceof VeilError && re.test(e.message));
  };
  await bad((q) => (q[4] = 2), /unsupported VEIL version/);
  await bad((q) => (q[5] = 9), /unsupported KDF id/);
  await bad((q) => (q[6] = 0), /stage count/);
  await bad((q) => (q[6] = 33), /stage count/);
  await bad((q) => q.writeUInt32BE(0, 24), /iterations per stage/);
  await bad((q) => q.writeUInt32BE(100001, 24), /iterations per stage/);
});
