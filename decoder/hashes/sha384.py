"""SHA-384 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA384Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA-384 producing a 96-char hex digest."""

    @property
    def name(self) -> str:
        return "sha384"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (96,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha384(text.encode("utf-8")).hexdigest()