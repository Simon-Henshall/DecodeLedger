"""Shared interface for cipher crackers."""

from abc import ABC, abstractmethod


class Cipher(ABC):
    """Blueprint for a cipher cracker."""

    name = "unknown"

    @abstractmethod
    def crack(self, ciphertext: str) -> list[str]:
        """Return plausible plaintext candidates for ciphertext."""
        raise NotImplementedError
