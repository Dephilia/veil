// Inlines src/veil.js into public/decrypt.html between the VEIL-CRYPTO markers.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('..', import.meta.url);
const START = '/* VEIL-CRYPTO:START */';
const END = '/* VEIL-CRYPTO:END */';

export function inlineSource() {
  const src = readFileSync(new URL('src/veil.js', root), 'utf8');
  if (/<\/script/i.test(src)) throw new Error('veil.js contains </script');
  // Classic inline script: drop `export` so declarations become plain globals.
  return src.replace(/^export\s+/gm, '').trim();
}

export function buildPages() {
  const file = fileURLToPath(new URL('public/decrypt.html', root));
  const html = readFileSync(file, 'utf8');
  const a = html.indexOf(START);
  const b = html.indexOf(END);
  if (a < 0 || b < a) throw new Error('markers not found in decrypt.html');
  const out = html.slice(0, a + START.length) + '\n' + inlineSource() + '\n' + html.slice(b);
  writeFileSync(file, out);
  return file;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log('built', buildPages());
