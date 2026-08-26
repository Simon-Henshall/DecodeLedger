"""BLAKE2s (BLAKE2 256-bit) cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class Blake2SHash(HashAlgorithm):
    """Lightweight wrapper around hashlib's BLAKE2s producing a 64-char hex digest."""

    @property
    def name(self) -> str:
        return "blake2s"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (64,)

    def hash_text(self, text: str) -> str:
        return hashlib.blake2s(text.encode("utf-8")).hexdigest()