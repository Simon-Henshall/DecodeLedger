"""Shared interface for cryptographic hash crackers."""

from abc import ABC, abstractmethod


class HashAlgorithm(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the hashing algorithm (e.g., 'md5', 'sha256')."""
        pass

    @property
    @abstractmethod
    def digest_sizes(self) -> tuple[int, ...]:
        """Valid lengths of the ciphertext in characters (hex string lengths)."""
        pass

    @abstractmethod
    def hash_text(self, text: str) -> str:
        """Hash a plaintext string to its hex format."""
        pass