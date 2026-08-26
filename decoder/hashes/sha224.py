"""SHA-224 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA224Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA-224 producing a 56-char hex digest."""

    @property
    def name(self) -> str:
        return "sha224"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (56,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha224(text.encode("utf-8")).hexdigest()