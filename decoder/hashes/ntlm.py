"""NTLM password hash (MD4 of the UTF-16LE encoding of the plaintext).

Modern OpenSSL builds no longer expose MD4 through hashlib, so this module
carries a compact pure-Python implementation of the MD4 message digest
(RFC 1320) and derives the standard NTLM response from it. The resulting
digest is a 32-character hex string, matching a 16-byte (128-bit) hash.
"""

from __future__ import annotations

import struct

from .base import HashAlgorithm

_MASK = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    """Rotate a 32-bit integer left by ``count`` bits."""
    return ((value << count) & _MASK) | (value >> (32 - count))


def _md4(data: bytes) -> bytes:
    """Return the raw 16-byte RFC 1320 MD4 digest of ``data``."""
    bit_length = len(data) * 8
    padded = data + b"\x80" + b"\x00" * ((56 - len(data) - 1) % 64) + struct.pack("<Q", bit_length)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    round_two_order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    round_three_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)

    for offset in range(0, len(padded), 64):
        words = struct.unpack("<16I", padded[offset : offset + 64])
        a, b, c, d = a0, b0, c0, d0

        # Round 1: F(x, y, z) = (x & y) | (~x & z)
        for index in range(16):
            shift = (3, 7, 11, 19)[index % 4]
            f = (b & c) | (~b & d)
            a = _rotl((a + f + words[index]) & _MASK, shift)
            a, b, c, d = d, a, b, c

        # Round 2: G(x, y, z) = (x & y) | (x & z) | (y & z)
        for index in range(16):
            shift = (3, 5, 9, 13)[index % 4]
            g = (b & c) | (b & d) | (c & d)
            a = _rotl((a + g + words[round_two_order[index]] + 0x5A827999) & _MASK, shift)
            a, b, c, d = d, a, b, c

        # Round 3: H(x, y, z) = x ^ y ^ z
        for index in range(16):
            shift = (3, 9, 11, 15)[index % 4]
            h = (b ^ c) ^ d
            a = _rotl((a + h + words[round_three_order[index]] + 0x6ED9EBA1) & _MASK, shift)
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & _MASK
        b0 = (b0 + b) & _MASK
        c0 = (c0 + c) & _MASK
        d0 = (d0 + d) & _MASK

    return struct.pack("<4I", a0, b0, c0, d0)


class NTLMHash(HashAlgorithm):
    """NTLM response: MD4 of the plaintext encoded as UTF-16LE, a 32-char hex digest."""

    @property
    def name(self) -> str:
        return "ntlm"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (32,)

    def hash_text(self, text: str) -> str:
        return _md4(text.encode("utf-16-le")).hex()