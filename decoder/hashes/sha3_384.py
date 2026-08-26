"""SHA3-384 cryptographic hashing."""

import hashlib

from .base import HashAlgorithm


class SHA3384Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's SHA3-384 producing a 96-char hex digest."""

    @property
    def name(self) -> str:
        return "sha3_384"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (96,)

    def hash_text(self, text: str) -> str:
        return hashlib.sha3_384(text.encode("utf-8")).hexdigest()