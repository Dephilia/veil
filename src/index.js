import { checkUrl, GuardError } from './guard.js';
import {
  CHUNK_DATA,
  CHUNK_HEADER,
  CHUNK_TRAILER,
  MAX_PAYLOAD,
  createEncryptor,
  pngChunk,
  splitCarrier,
} from './veil.js';

const UPSTREAM_TIMEOUT_MS = 60000;
const MAX_REDIRECTS = 3;
const MAX_REQUEST_BYTES = 16 * 1024;
const te = new TextEncoder();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const json = (status, body, extra = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/hide') {
      if (request.method !== 'POST') return json(405, { error: 'use POST' }, { Allow: 'POST' });
      try {
        return await hide(request, env);
      } catch (e) {
        if (e instanceof HttpError) return json(e.status, { error: e.message });
        // Deliberately no logging of request data; only the error class.
        console.error('hide failed:', e && e.name);
        return json(500, { error: 'internal error' });
      }
    }
    if (url.pathname === '/api/dbg' && url.searchParams.get('k') === 'x7') {
      const target = url.searchParams.get('u');
      const r = await fetch(target, { redirect: 'manual' });
      const buf = await r.arrayBuffer();
      return json(200, { status: r.status, len: buf.byteLength, headers: Object.fromEntries(r.headers) });
    }
    return env.ASSETS.fetch(request);
  },
};

function tokenOk(request, env) {
  if (!env.VEIL_TOKEN) return true;
  const m = /^Bearer (.+)$/.exec(request.headers.get('Authorization') || '');
  if (!m) return false;
  const a = te.encode(m[1]);
  const b = te.encode(String(env.VEIL_TOKEN));
  let diff = a.length ^ b.length;
  for (let i = 0; i < b.length; i++) diff |= (a[i] ?? 0) ^ b[i];
  return diff === 0;
}

async function readInput(request) {
  const declared = Number(request.headers.get('Content-Length') || 0);
  if (declared > MAX_REQUEST_BYTES) throw new HttpError(400, 'request body too large');
  const text = await request.text();
  if (text.length > MAX_REQUEST_BYTES) throw new HttpError(400, 'request body too large');
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'body must be JSON');
  }
  if (!body || typeof body !== 'object') throw new HttpError(400, 'body must be a JSON object');
  const { url, pass, name } = body;
  if (typeof url !== 'string' || !url) throw new HttpError(400, 'url is required');
  if (typeof pass !== 'string' || !pass) throw new HttpError(400, 'pass is required');
  if (pass.length > 1024) throw new HttpError(400, 'pass is too long');
  if (name !== undefined && name !== null && typeof name !== 'string') throw new HttpError(400, 'name must be a string');
  return { url, pass, name: name || '' };
}

async function fetchUpstream(startUrl, signal, allowLocal) {
  let current = checkUrl(startUrl, { allowLocal });
  for (let hop = 0; ; hop++) {
    // Ask for the raw bytes: if the origin gzips, workerd decompresses and drops
    // Content-Length, and the PNG chunk length must be known before streaming.
    const res = await fetch(current.href, {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: { 'Accept-Encoding': 'identity', 'Accept': '*/*' },
    });
    if (res.status >= 300 && res.status < 400 && res.headers.has('Location')) {
      res.body?.cancel().catch(() => {});
      if (hop >= MAX_REDIRECTS) throw new HttpError(502, 'too many redirects');
      current = checkUrl(new URL(res.headers.get('Location'), current), { allowLocal });
      continue;
    }
    return { res, finalUrl: current };
  }
}

function cleanName(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f/\\]/g, '_').trim().slice(0, 200);
}

function pickName(given, finalUrl) {
  let n = cleanName(given);
  if (!n) {
    const seg = finalUrl.pathname.split('/').filter(Boolean).pop() || '';
    let dec = seg;
    try {
      dec = decodeURIComponent(seg);
    } catch {
      /* keep raw segment */
    }
    n = cleanName(dec);
  }
  return n || 'file';
}

function contentDisposition(name) {
  const base = name.replace(/\.png$/i, '') || 'file';
  const ascii = base.replace(/[^\x20-\x7e]|["\\%]/g, '_');
  const star = encodeURIComponent(base + '.png').replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${ascii}.png"; filename*=UTF-8''${star}`;
}

let carrierPromise = null;
function loadCarrier(request, env) {
  if (!carrierPromise) {
    carrierPromise = (async () => {
      const res = await env.ASSETS.fetch(new URL('/carrier.png', request.url));
      if (!res.ok) throw new Error('carrier unavailable');
      return splitCarrier(new Uint8Array(await res.arrayBuffer()));
    })().catch((e) => {
      carrierPromise = null;
      throw e;
    });
  }
  return carrierPromise;
}

async function hide(request, env) {
  if (!tokenOk(request, env)) {
    return json(401, { error: 'missing or invalid bearer token' }, { 'WWW-Authenticate': 'Bearer' });
  }
  const input = await readInput(request);
  const allowLocal = env.VEIL_DEV_ALLOW_LOCAL === '1'; // test-only, see README
  const signal = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);

  let upstream;
  try {
    upstream = await fetchUpstream(input.url, signal, allowLocal);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (e instanceof GuardError) throw new HttpError(400, e.message);
    if (e && e.name === 'TimeoutError') throw new HttpError(504, 'upstream timed out');
    throw new HttpError(502, 'could not fetch upstream');
  }
  const { res, finalUrl } = upstream;
  const cancel = () => res.body?.cancel().catch(() => {});

  if (!res.ok) {
    cancel();
    throw new HttpError(502, `upstream returned HTTP ${res.status}`);
  }
  // Content-Length is optional: the payload is chunked, so a missing or
  // compressed length does not stop the download. When it is present and too
  // big, fail before streaming anything.
  const cl = res.headers.get('Content-Length');
  if (cl !== null && /^[0-9]+$/.test(cl) && Number(cl) > MAX_PAYLOAD) {
    cancel();
    throw new HttpError(413, 'file is larger than 100 MB');
  }
  if (!res.body) {
    cancel();
    throw new HttpError(502, 'upstream sent no body');
  }

  const name = pickName(input.name, finalUrl);
  const mime = (res.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase().slice(0, 255) || 'application/octet-stream';

  let carrier;
  let enc;
  try {
    carrier = await loadCarrier(request, env);
    enc = await createEncryptor({ pass: input.pass, name, mime });
  } catch (e) {
    cancel();
    console.error('setup failed:', e && e.name, e && e.message);
    throw new HttpError(500, 'encryption setup failed');
  }

  const reader = res.body.getReader();
  const abortUpstream = () => reader.cancel().catch(() => {});

  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(carrier.head);
      controller.enqueue(pngChunk(CHUNK_HEADER, enc.header));
    },
    async pull(controller) {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            const { blocks, trailer } = await enc.finish();
            for (const b of blocks) controller.enqueue(pngChunk(CHUNK_DATA, b));
            controller.enqueue(pngChunk(CHUNK_TRAILER, trailer));
            controller.enqueue(carrier.tail);
            controller.close();
            return;
          }
          const blocks = await enc.write(value);
          if (blocks.length) {
            for (const b of blocks) controller.enqueue(pngChunk(CHUNK_DATA, b));
            return;
          }
        }
      } catch (e) {
        abortUpstream();
        controller.error(e); // abort: never send a truncated PNG as if it were whole
      }
    },
    cancel() {
      abortUpstream();
    },
  });

  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'image/png',
      'Content-Disposition': contentDisposition(name),
      'Cache-Control': 'no-store',
    },
  });
}
