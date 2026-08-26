"""SHA-1 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA1Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA-1 producing a 40-char hex digest."""

    @property
    def name(self) -> str:
        return "sha1"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (40,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()