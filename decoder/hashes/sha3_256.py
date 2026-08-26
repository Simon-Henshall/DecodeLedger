"""SHA3-256 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA3256Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA3-256 producing a 64-char hex digest."""

    @property
    def name(self) -> str:
        return "sha3_256"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (64,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha3_256(text.encode("utf-8")).hexdigest()