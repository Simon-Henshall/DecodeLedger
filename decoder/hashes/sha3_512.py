"""SHA3-512 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA3512Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA3-512 producing a 128-char hex digest."""

    @property
    def name(self) -> str:
        return "sha3_512"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (128,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha3_512(text.encode("utf-8")).hexdigest()