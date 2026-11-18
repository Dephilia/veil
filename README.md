# veil

Cloudflare Worker that fetches a file server-side, encrypts it (AES-256-GCM, chained PBKDF2-SHA-256, 6 × 100 000 rounds)
and hides it in a real PNG (`public/carrier.png`). `public/decrypt.html` restores it fully offline.

## Container (v3)

The payload lives in private ancillary chunks placed after the last IDAT, so **no total length has to be known before
streaming starts** — an upstream without `Content-Length` (chunked, gzipped by a CDN, anything) works:

| chunk | contents |
| --- | --- |
| `tOMh` | header, 40 B: `"VEIL"`, version 3, kdfId, stages, salt(16), itersPerStage, blockSize, nonceTag(8) |
| `tOMd` | one per block, in order: `u32 index` + AES-256-GCM block + 16 B tag (block size 1 MiB) |
| `tOMt` | trailer, 44 B: `u32 blockCount`, `u64 plainLen`, `rootHash` (SHA-256 of the framed plaintext) |

Framed plaintext = `u32 jsonLen` | `{"name","mime"}` | file bytes. Per-block nonce = `nonceTag || u32 index`,
AAD = `"VEIL" || u32 index`, so a block moved into another slot fails authentication; a missing trailer or a removed block
fails the count check and the rootHash.

- `src/veil.js` — the single source of truth for the format (runs in Worker, browser, Node).
- `src/guard.js` — SSRF guard. `src/index.js` — Worker.
- `npm run build:pages` inlines `src/veil.js` into `public/decrypt.html` between the `VEIL-CRYPTO` markers. Re-run after editing `veil.js` (a test fails if it is stale).
- `npm test` — unit tests (needs python3 + PIL). `npm run test:integration` — starts python http.server + two `wrangler dev` instances.

## Security notes

- **DNS rebinding cannot be checked from inside Workers.** The guard validates the URL text (scheme, port, credentials, hostname
  suffixes, IP literals at every redirect hop). Workers have no DNS API, so a public hostname that *resolves* to a private
  address is not detected. Cloudflare's network not routing to your private ranges is the real backstop.
- **`VEIL_TOKEN` is set on this deployment** (`wrangler secret put VEIL_TOKEN`). Without it anyone can use the Worker as a
  download proxy up to 100 MB per request. The index page shows a token field after the first 401; the token is not in git.
- The guard additionally blocks `::/96` and `64:ff9b::/96` (embedded IPv4) beyond the required list.
- `VEIL_DEV_ALLOW_LOCAL=1` disables the host/port rules. It exists only so the integration test can reach a loopback server;
  it is passed via `--var` by the test and must never be put in `wrangler.jsonc` or set in production.
- Nothing logs the passphrase, URL query or content.
- Hiding is not concealment: anyone who parses the PNG chunks sees `tOMh`/`tOMd`/`tOMt` immediately. The encryption is what
  protects the contents. Re-saving the image through an editor drops the chunks and the file with them.

## Key derivation

The key is a chain of six native PBKDF2-HMAC-SHA-256 calls (`STAGES = 6`, `ITERS_PER_STAGE = 100000`, 32-byte output):
`s = salt; for k in 0..5: out = PBKDF2(pass, s, 100000, 32); s = out; key = out`. Total work is about 600 000 iterations.

**Why a chain:** production workerd hard-caps PBKDF2 at 100 000 iterations (`NotSupportedError: iteration counts above
100000 are not supported`), while local `wrangler dev` accepts 600 000 — so a single 600 000-round call would work in dev and
fail when deployed. Each stage stays at the cap; chaining keeps the cost with native PBKDF2. The same code in `src/veil.js` is
used by the Worker, the browser and Node.

The header stores `stages` and `itersPerStage`, and the decryptor re-derives from those values (rejecting `stages` 0 or > 32,
`itersPerStage` outside 1..100000, or `stages * itersPerStage > 6 000 000`), so a future cost change stays readable.
`tests/kdf_vectors.json` holds frozen vectors from the Python reference `tests/kdf_ref.py`; `tests/kdf.test.mjs` checks them.

**Passphrase advice:** the work factor is modest, so the passphrase carries the security. Use the "Generate passphrase" button
(24 characters of base32 from `crypto.getRandomValues`, 120 bits) and send it to the recipient separately from the PNG.

## Known limits

- The 60 s upstream timeout (`AbortSignal.timeout`) covers the whole download, not just time-to-headers.
- CPU: the rootHash needs incremental SHA-256, which WebCrypto lacks, so it is done in JS (about 2 s CPU per 100 MB in Node/V8)
  plus per-block CRC-32. This needs a Workers plan with a CPU limit above the free tier's 10 ms.
- The browser holds the whole PNG in memory before the download starts; above ~100 MB that is uncomfortable.
- A PNG carries ~100 MB of payload comfortably; past that the chunk count and the browser memory both grow.
