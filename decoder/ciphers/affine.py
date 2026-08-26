"""Affine cipher cracking by trying every valid key pair."""

from math import gcd

from .base import Cipher


class AffineCipher(Cipher):
    name = "affine"

    def crack(self, ciphertext: str) -> list[str]:
        candidates = []
        for multiplier in range(26):
            if gcd(multiplier, 26) != 1:
                continue
            inverse = pow(multiplier, -1, 26)
            for offset in range(26):
                candidates.append(self._decrypt(ciphertext, multiplier, inverse, offset))
        return candidates

    @staticmethod
    def _decrypt(text: str, multiplier: int, inverse: int, offset: int) -> str:
        result = []
        for character in text:
            if character.isalpha() and character.isascii():
                base = ord("A") if character.isupper() else ord("a")
                encrypted = ord(character) - base
                decrypted = inverse * (encrypted - offset) % 26
                result.append(chr(base + decrypted))
            else:
                result.append(character)
        return "".join(result)