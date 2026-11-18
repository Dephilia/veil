// Loads the crypto exactly as inlined in public/decrypt.html (between the markers).
import { readFileSync } from 'node:fs';

export function loadInlined(htmlPath = new URL('../public/decrypt.html', import.meta.url)) {
  const html = readFileSync(htmlPath, 'utf8');
  const a = html.indexOf('/* VEIL-CRYPTO:START */');
  const b = html.indexOf('/* VEIL-CRYPTO:END */');
  if (a < 0 || b < a) throw new Error('markers not found');
  const code = html.slice(a, b);
  return new Function(`${code}\nreturn { decryptContainer, openVeil, pngChunk, VeilError, Sha256, CHUNK_HEADER, CHUNK_DATA, CHUNK_TRAILER };`)();
}
