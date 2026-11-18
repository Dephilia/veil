#!/usr/bin/env node
// usage: decrypt-cli.mjs <png> <pass> <out>   — uses the code inlined in decrypt.html
import { readFileSync, writeFileSync } from 'node:fs';
import { loadInlined } from './extract-inlined.mjs';

const [png, pass, out] = process.argv.slice(2);
if (!png || pass === undefined || !out) {
  console.error('usage: decrypt-cli.mjs <png> <pass> <out>');
  process.exit(2);
}
const { decryptContainer, openVeil } = loadInlined();
const bytes = new Uint8Array(readFileSync(png));
const container = openVeil(bytes);
if (!container) {
  console.error('no VEIL chunks found');
  process.exit(1);
}
try {
  const r = await decryptContainer(container, pass);
  writeFileSync(out, r.bytes);
  console.log(JSON.stringify({ name: r.name, mime: r.mime, size: r.size, rootHash: r.rootHash }));
} catch (e) {
  console.error('decrypt failed:', e.message);
  process.exit(1);
}
