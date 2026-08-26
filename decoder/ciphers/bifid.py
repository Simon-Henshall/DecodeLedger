"""Bifid cipher cracking with common keys and periods."""

from .base import Cipher


class BifidCipher(Cipher):
    name = "bifid"
    common_keys = ("keyword", "cipher", "secret", "bifid", "monarchy")
    periods = (5, 7, 10)

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if not letters:
            return []
        candidates = [self._decrypt(letters, key, period) for key in self.common_keys for period in self.periods]
        return list(dict.fromkeys(candidates))

    @staticmethod
    def _square(key: str) -> tuple[str, dict[str, tuple[int, int]]]:
        alphabet = "abcdefghiklmnopqrstuvwxyz"
        sequence = ""
        for character in key.lower() + alphabet:
            if character == "j":
                character = "i"
            if character in alphabet and character not in sequence:
                sequence += character
        positions = {character: (index // 5 + 1, index % 5 + 1) for index, character in enumerate(sequence)}
        return sequence, positions

    @classmethod
    def _decrypt(cls, text: str, key: str, period: int) -> str:
        square, positions = cls._square(key)
        plaintext = []
        for start in range(0, len(text), period):
            block = text[start : start + period]
            coordinates = [coordinate for character in block for coordinate in positions[character.replace("j", "i")]]
            midpoint = len(block)
            rows, columns = coordinates[:midpoint], coordinates[midpoint:]
            plaintext.extend(square[(row - 1) * 5 + column - 1] for row, column in zip(rows, columns))
        return "".join(plaintext)