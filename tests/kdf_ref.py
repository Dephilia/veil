#!/usr/bin/env python3
"""Reference VEIL KDF: six chained PBKDF2-HMAC-SHA256 stages (hashlib).

  kdf_ref.py <passphrase> <salt-hex>   -> prints key hex
  kdf_ref.py --vectors                 -> prints the frozen-vector JSON
"""
import hashlib, json, sys

STAGES = 6
ITERS = 100000


def derive(pw: bytes, salt: bytes, stages=STAGES, iters=ITERS) -> bytes:
    s = salt
    out = b""
    for _ in range(stages):
        out = hashlib.pbkdf2_hmac("sha256", pw, s, iters, 32)
        s = out
    return out


CASES = [
    ("correct horse battery staple", "000102030405060708090a0b0c0d0e0f"),
    ("パスフレーズ🔐ü", "ffeeddccbbaa99887766554433221100"),
    ("", "a1a2a3a4a5a6a7a8a9aaabacadaeafb0"),
    ("short", "7f"),
    ("x" * 200, "00" * 16),
    ("ABCDEFGHJKLMNPQRSTUVWXYZ", "0123456789abcdef0123456789abcdef"),
]


def vectors():
    return [
        {"passphrase": p, "salt": s, "key": derive(p.encode("utf-8"), bytes.fromhex(s)).hex()}
        for p, s in CASES
    ]


if __name__ == "__main__":
    if sys.argv[1:] == ["--vectors"]:
        print(json.dumps(vectors(), ensure_ascii=False, indent=2))
    elif len(sys.argv) == 3:
        print(derive(sys.argv[1].encode("utf-8"), bytes.fromhex(sys.argv[2])).hex())
    else:
        sys.exit(__doc__)
