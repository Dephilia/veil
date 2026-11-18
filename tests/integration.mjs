// End-to-end: python http.server (60 MB) -> wrangler dev -> /api/hide -> PIL -> decrypt-cli -> sha256.
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const root = new URL('..', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), 'veil-int-'));
const procs = [];
const sha = (b) => createHash('sha256').update(b).digest('hex');
const PASS = 'integration pässphrase ✓';
const PY = 18431, ND = 18432, W1 = 8787, W2 = 8788;
const ms = (t) => `${(performance.now() - t).toFixed(0)} ms`;
const sleep = (n) => new Promise((r) => setTimeout(r, n));

function spawnBg(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { detached: true, stdio: ['ignore', 'pipe', 'pipe'], ...opts });
  let log = '';
  p.stdout.on('data', (d) => (log += d));
  p.stderr.on('data', (d) => (log += d));
  p.getLog = () => log;
  procs.push(p);
  return p;
}
function cleanup() {
  for (const p of procs) try { process.kill(-p.pid, 'SIGTERM'); } catch {}
  rmSync(tmp, { recursive: true, force: true });
}
async function waitFor(url, what, p) {
  for (let i = 0; i < 90; i++) {
    try { await fetch(url); return; } catch { await sleep(500); }
  }
  throw new Error(`${what} did not start\n${p?.getLog?.()}`);
}
const hide = (port, body, headers = {}) =>
  fetch(`http://127.0.0.1:${port}/api/hide`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const probe = (f) => JSON.parse(execFileSync('python3', ['-I', join(root, 'tests/png_probe.py'), f]).toString());
const cli = (png, out) => execFileSync('node', [join(root, 'tools/decrypt-cli.mjs'), png, PASS, out]).toString().trim();

let failed = false;
try {
  const data = randomBytes(60 * 1000 * 1000);
  writeFileSync(join(tmp, 'blob.bin'), data);
  const srcSha = sha(data);
  spawnBg('python3', ['-m', 'http.server', String(PY), '--bind', '127.0.0.1'], { cwd: tmp });

  // edge-case upstream: no Content-Length / oversize declared / short body / redirect / 404
  http.createServer((req, res) => {
    if (req.url.startsWith('/nolen')) { res.writeHead(200, { 'Transfer-Encoding': 'chunked' }); res.write('hello'); return res.end(); }
    if (req.url.startsWith('/huge')) { res.writeHead(200, { 'Content-Length': String(100 * 1024 * 1024 + 1) }); return res.flushHeaders(); }
    if (req.url.startsWith('/short')) {
      res.writeHead(200, { 'Content-Length': String(5_000_000) });
      res.write(Buffer.alloc(2_000_000, 7));
      return setTimeout(() => res.end(), 300);
    }
    if (req.url.startsWith('/missing')) { res.writeHead(404, { 'Content-Length': '0' }); return res.end(); }
    res.writeHead(500); res.end();
  }).listen(ND, '127.0.0.1');

  const env = { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' };
  const w1 = spawnBg('npx', ['wrangler', 'dev', '--port', String(W1), '--inspector-port', '0', '--var', 'VEIL_DEV_ALLOW_LOCAL:1'], { cwd: root, env });
  const w2 = spawnBg('npx', ['wrangler', 'dev', '--port', String(W2), '--inspector-port', '0', '--var', 'VEIL_TOKEN:s3cret', '--persist-to', join(tmp, 'w2')], { cwd: root, env });
  await Promise.all([
    waitFor(`http://127.0.0.1:${PY}/`, 'python server'),
    waitFor(`http://127.0.0.1:${W1}/`, 'wrangler #1', w1),
    waitFor(`http://127.0.0.1:${W2}/`, 'wrangler #2', w2),
  ]);

  // 1. main flow, 60 MB
  let t = performance.now();
  const res = await hide(W1, { url: `http://127.0.0.1:${PY}/blob.bin?secret=1`, pass: PASS, name: 'my blob ü.bin' });
  assert.equal(res.status, 200, await res.clone().text());
  assert.equal(res.headers.get('content-type'), 'image/png');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  console.log('content-disposition:', res.headers.get('content-disposition'));
  const png = Buffer.from(await res.arrayBuffer());
  console.log(`hide 60 MB (${data.length} B in): ${png.length} B PNG in ${ms(t)}`);
  const pngPath = join(tmp, 'out.png');
  writeFileSync(pngPath, png);
  const pr = probe(pngPath);
  assert.deepEqual(pr.size, [1600, 1000]);
  assert.equal(pr.mode, 'RGB');
  assert.equal(pr.format, 'PNG', 'PIL must open the produced PNG');
  console.log(`PIL opens PNG: size=${pr.size} mode=${pr.mode}`);
  t = performance.now();
  const outPath = join(tmp, 'restored.bin');
  const meta = cli(pngPath, outPath);
  console.log(`decrypt-cli (inlined decrypt.html code): ${meta} in ${ms(t)}`);
  assert.equal(sha(readFileSync(outPath)), srcSha);
  assert.equal(JSON.parse(meta).name, 'my blob ü.bin');
  console.log(`SHA-256 match: ${srcSha}`);
  let code = 0;
  try { execFileSync('node', [join(root, 'tools/decrypt-cli.mjs'), pngPath, 'wrong', join(tmp, 'x')], { stdio: 'pipe' }); } catch (e) { code = e.status; }
  assert.notEqual(code, 0);
  console.log('wrong passphrase rejected by CLI');

  // 2. error contract (no Content-Length is fine now: the payload is chunked)
  let r = await hide(W1, { url: `http://127.0.0.1:${ND}/nolen`, pass: PASS });
  assert.equal(r.status, 200, 'chunked upstream must still work');
  {
    const p = join(tmp, 'nolen.png');
    writeFileSync(p, Buffer.from(await r.arrayBuffer()));
    const o = join(tmp, 'nolen.out');
    cli(p, o);
    assert.equal(readFileSync(o, 'utf8'), 'hello');
  }
  r = await hide(W1, { url: `http://127.0.0.1:${ND}/huge`, pass: 'x' });
  assert.equal(r.status, 413);
  r = await hide(W1, { url: `http://127.0.0.1:${ND}/missing`, pass: 'x' });
  assert.equal(r.status, 502);
  r = await hide(W1, { pass: 'x' });
  assert.equal(r.status, 400);
  r = await hide(W1, { url: 'ftp://x/y', pass: 'x' });
  assert.equal(r.status, 400);
  r = await fetch(`http://127.0.0.1:${W1}/api/hide`, { method: 'POST', body: 'nope' });
  assert.equal(r.status, 400);
  console.log('status contract OK');

  // 3. an upstream that lies about Content-Length: the fetch stream errors, so
  //    the response is aborted rather than finished as a valid-looking PNG.
  r = await hide(W1, { url: `http://127.0.0.1:${ND}/short`, pass: PASS });
  let aborted = false;
  try { await r.arrayBuffer(); } catch { aborted = true; }
  assert.ok(aborted, 'stream must abort when the upstream body ends short');
  console.log('short upstream body -> response stream aborted OK');

  // 4. guard end-to-end + token gate (instance #2: no dev flag, VEIL_TOKEN set)
  r = await hide(W2, { url: 'http://example.com/', pass: 'x' });
  assert.equal(r.status, 401);
  r = await hide(W2, { url: 'http://example.com/', pass: 'x' }, { authorization: 'Bearer wrong' });
  assert.equal(r.status, 401);
  r = await hide(W2, { url: `http://127.0.0.1:${PY}/blob.bin`, pass: 'x' }, { authorization: 'Bearer s3cret' });
  assert.equal(r.status, 400);
  console.log('guard (no dev flag) ->', r.status, JSON.stringify(await r.json()));
  r = await hide(W2, { url: 'http://169.254.169.254/', pass: 'x' }, { authorization: 'Bearer s3cret' });
  assert.equal(r.status, 400);
  assert.equal((await fetch(`http://127.0.0.1:${W2}/decrypt.html`)).status, 200);
  assert.equal((await fetch(`http://127.0.0.1:${W2}/`)).status, 200);
  console.log('token gate + SSRF guard + static assets OK');

  // 5. no secrets in worker logs
  const logs = w1.getLog() + w2.getLog();
  assert.ok(!logs.includes(PASS) && !logs.includes('secret=1'), 'secrets leaked into logs');
  console.log('no passphrase/query string in wrangler logs OK');
  console.log('\nINTEGRATION PASSED');
} catch (e) {
  failed = true;
  console.error('\nINTEGRATION FAILED:', e);
} finally {
  cleanup();
  process.exit(failed ? 1 : 0);
}
