import test from 'node:test';
import assert from 'node:assert/strict';
import { checkUrl, GuardError } from '../src/guard.js';

const bad = [
  'ftp://example.com/x', 'file:///etc/passwd', 'javascript:alert(1)', 'not a url',
  'http://localhost/x', 'http://localhost./x', 'http://a.localhost/x', 'http://printer.local/x', 'http://db.internal/x',
  'http://router.home.arpa/x', 'http://LOCALHOST/',
  'http://0.0.0.0/', 'http://0.1.2.3/', 'http://10.1.2.3/', 'http://100.64.0.1/', 'http://100.127.255.255/',
  'http://127.0.0.1/', 'http://127.255.0.9/', 'http://169.254.169.254/latest/meta-data', 'http://172.16.0.1/', 'http://172.31.255.255/',
  'http://192.168.1.1/', 'http://192.0.0.8/', 'http://198.18.0.1/', 'http://198.19.255.255/', 'http://224.0.0.1/', 'http://240.0.0.1/', 'http://255.255.255.255/',
  'http://2130706433/', 'http://0x7f.1/', 'http://0177.0.0.1/', 'http://127.1/',
  'http://[::1]/', 'http://[::]/', 'http://[fc00::1]/', 'http://[fd12:3456::1]/', 'http://[fe80::1]/', 'http://[febf::1]/',
  'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/', 'http://[::ffff:10.0.0.1]/', 'http://[::ffff:a9fe:a9fe]/',
  'http://[0:0:0:0:0:0:0:1]/', 'http://[::127.0.0.1]/', 'http://[64:ff9b::7f00:1]/',
  'http://user:pw@example.com/', 'http://user@example.com/', 'https://:pw@example.com/',
  'http://example.com:8080/', 'https://example.com:8443/', 'http://example.com:22/',
];
const good = [
  'http://example.com/a', 'https://example.com/a?x=1', 'https://example.com:443/a', 'http://example.com:80/', 'http://8.8.8.8/',
  'http://172.32.0.1/', 'http://100.128.0.1/', 'http://198.20.0.1/', 'http://223.255.255.255/', 'http://192.0.2.1/',
  'https://[2606:4700:4700::1111]/', 'http://[::ffff:8.8.8.8]/', 'http://[2001:db8::1]/', 'https://localhost.example.com/',
];

for (const u of bad) test(`rejects ${u}`, () => assert.throws(() => checkUrl(u), GuardError));
for (const u of good) test(`allows ${u}`, () => assert.ok(checkUrl(u)));

test('allowLocal only relaxes host/port, not scheme or credentials', () => {
  assert.ok(checkUrl('http://127.0.0.1:9999/', { allowLocal: true }));
  assert.throws(() => checkUrl('ftp://127.0.0.1/', { allowLocal: true }), GuardError);
  assert.throws(() => checkUrl('http://u:p@127.0.0.1/', { allowLocal: true }), GuardError);
});
