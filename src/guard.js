// SSRF guard. Applied to the initial URL and to every redirect hop.
// NOTE: this is a syntactic check on the URL. It cannot see what a hostname
// resolves to (DNS rebinding) — Workers expose no DNS API. See README.

export class GuardError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GuardError';
  }
}

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];
const BLOCKED_NAMES = new Set(['localhost', 'local', 'internal', 'home.arpa']);

// [network, prefix length] over a 32-bit unsigned address.
const V4_BLOCKS = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['192.0.0.0', 24],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
].map(([ip, bits]) => [parseV4(ip), bits]);

function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function v4Blocked(n) {
  return V4_BLOCKS.some(([net, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((net & mask) >>> 0);
  });
}

// Parses an IPv6 literal (no brackets) to 8 16-bit groups, or null.
function parseV6(s) {
  if (s.includes('%')) return null; // zone ids never appear in valid URLs
  let tail = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (dotted) {
    const v4 = parseV4(dotted[1]);
    if (v4 === null) return null;
    tail = [v4 >>> 16, v4 & 0xffff];
    s = s.slice(0, -dotted[1].length) + '0:0';
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part) => (part === '' ? [] : part.split(':'));
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  const total = head.length + rest.length;
  if (halves.length === 1 ? total !== 8 : total > 7) return null;
  const groups = [...head, ...Array(8 - total).fill('0'), ...rest];
  const out = groups.map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN));
  if (out.some(Number.isNaN)) return null;
  if (tail.length) {
    out[6] = tail[0];
    out[7] = tail[1];
  }
  return out;
}

function v6Blocked(g) {
  const allZero5 = g.slice(0, 5).every((x) => x === 0);
  if (g.slice(0, 7).every((x) => x === 0)) return true; // :: and ::1
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10
  const embedded = ((g[6] << 16) | g[7]) >>> 0;
  if (allZero5 && g[5] === 0xffff) return v4Blocked(embedded); // ::ffff:0:0/96 mapped v4
  if (allZero5 && g[5] === 0) return v4Blocked(embedded); // ::/96 IPv4-compatible (extra)
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4Blocked(embedded); // NAT64 (extra)
  return false;
}

// Returns the parsed URL or throws GuardError. `allowLocal` is a dev/test-only
// switch (never set in wrangler.jsonc) that skips the host and port rules.
export function checkUrl(input, { allowLocal = false } = {}) {
  let url;
  try {
    url = input instanceof URL ? input : new URL(input);
  } catch {
    throw new GuardError('invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new GuardError('only http and https URLs are allowed');
  if (url.username || url.password) throw new GuardError('URLs with credentials are not allowed');
  if (allowLocal) return url;

  if (url.port !== '' && url.port !== '80' && url.port !== '443') throw new GuardError('only ports 80 and 443 are allowed');

  let host = url.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) {
    const g = parseV6(host.slice(1, -1));
    if (!g || v6Blocked(g)) throw new GuardError('address is not allowed');
    return url;
  }
  while (host.endsWith('.')) host = host.slice(0, -1);
  if (!host) throw new GuardError('invalid host');
  const v4 = parseV4(host);
  if (v4 !== null) {
    if (v4Blocked(v4)) throw new GuardError('address is not allowed');
    return url;
  }
  if (BLOCKED_NAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) throw new GuardError('host is not allowed');
  return url;
}
