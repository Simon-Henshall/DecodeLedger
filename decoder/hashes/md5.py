"""MD5 message-digest hashing."""

import hashlib

from .base import HashAlgorithm


class MD5Hash(HashAlgorithm):
    """Lightweight wrapper around hashlib's MD5 guaranteeing a 32-char hex digest."""

    @property
    def name(self) -> str:
        return "md5"

    @property
    def digest_sizes(self) -> tuple[int, ...]:
        return (32,)

    def hash_text(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8")).hexdigest()