import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { deriveKeyBytes, STAGES, ITERS_PER_STAGE } from '../src/veil.js';

const ref = new URL('./kdf_ref.py', import.meta.url).pathname;
const hex = (b) => Buffer.from(b).toString('hex');
const py = (pass, saltHex) => execFileSync('python3', ['-I', ref, pass, saltHex]).toString().trim();
const vectors = JSON.parse(readFileSync(new URL('./kdf_vectors.json', import.meta.url), 'utf8'));

test('parameters are 6 x 100000', () => {
  assert.equal(STAGES, 6);
  assert.equal(ITERS_PER_STAGE, 100000);
});

test('frozen vectors: at least 5, incl. UTF-8, empty passphrase, 1-byte salt', () => {
  assert.ok(vectors.length >= 5);
  assert.ok(vectors.some((v) => /[^\x00-\x7f]/.test(v.passphrase)));
  assert.ok(vectors.some((v) => v.passphrase === ''));
  assert.ok(vectors.some((v) => v.salt.length === 2));
});

test('src/veil.js reproduces every frozen vector bit for bit', async () => {
  for (const v of vectors) {
    const got = await deriveKeyBytes(v.passphrase, Buffer.from(v.salt, 'hex'));
    assert.equal(hex(got), v.key, JSON.stringify(v.passphrase));
  }
});

test('JS and Python agree on fresh random pairs', async () => {
  for (let i = 0; i < 3; i++) {
    const pass = randomBytes(8 + i * 5).toString('base64') + 'é';
    const salt = randomBytes(1 + Math.floor(Math.random() * 32)).toString('hex');
    const js = hex(await deriveKeyBytes(pass, Buffer.from(salt, 'hex')));
    assert.equal(js, py(pass, salt));
  }
});

test('equals a direct six-call chain (no off-by-one), JS and Python', async () => {
  const pass = 'chain check ü';
  const salt = randomBytes(16);
  let s = salt;
  for (let k = 0; k < 6; k++) s = pbkdf2Sync(Buffer.from(pass), s, 100000, 32, 'sha256');
  assert.equal(hex(await deriveKeyBytes(pass, salt)), hex(s));
  assert.equal(py(pass, salt.toString('hex')), hex(s));
  // 5 or 7 stages must differ
  const five = await deriveKeyBytes(pass, salt, 5);
  assert.notEqual(hex(five), hex(s));
});
