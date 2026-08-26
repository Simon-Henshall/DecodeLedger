"""BLAKE2b (BLAKE2 512-bit) cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class Blake2BHash(HashAlgorithm):
    """Lightweight wrapper around hashlib's BLAKE2b producing a 128-char hex digest."""

    @property
    def name(self) -> str:
        return "blake2b"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (128,)

    def hash_text(self, text: str) -> str:
        return hashlib.blake2b(text.encode("utf-8")).hexdigest()