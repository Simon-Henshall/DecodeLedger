"""SHA-3 (224-bit) cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA3224Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA3-224 producing a 56-char hex digest."""

    @property
    def name(self) -> str:
        return "sha3_224"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (56,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha3_224(text.encode("utf-8")).hexdigest()