"""Vigenere cipher cracking with common-key and frequency candidates."""

from collections import Counter
import string

from .base import Cipher
from ..intelligence.frequency import ENGLISH_FREQUENCIES


class VigenereCipher(Cipher):
    name = "vigenere"
    common_keys = ("key", "lemon", "secret", "cipher", "password", "hello")

    def crack(self, ciphertext: str) -> list[str]:
        candidates = [self._decrypt(ciphertext, key) for key in self.common_keys]
        candidates.extend(
            self._decrypt(ciphertext, self._estimate_key(ciphertext, length))
            for length in range(1, min(8, self._letter_count(ciphertext)) + 1)
        )
        return list(dict.fromkeys(candidates))

    @staticmethod
    def _letter_count(text: str) -> int:
        return sum(character.isalpha() and character.isascii() for character in text)

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        result = []
        key_index = 0
        for character in text:
            if character.isalpha() and character.isascii():
                base = ord("A") if character.isupper() else ord("a")
                shift = ord(key[key_index % len(key)].lower()) - ord("a")
                result.append(chr((ord(character) - base - shift) % 26 + base))
                key_index += 1
            else:
                result.append(character)
        return "".join(result)

    @staticmethod
    def _estimate_key(text: str, length: int) -> str:
        letters = [character.lower() for character in text if character.lower() in string.ascii_lowercase]
        key = []
        expected = [ENGLISH_FREQUENCIES[letter] for letter in string.ascii_lowercase]
        for position in range(length):
            column = letters[position::length]
            if not column:
                key.append("a")
                continue
            best_shift = min(
                range(26),
                key=lambda shift: VigenereCipher._column_score(column, shift, expected),
            )
            key.append(chr(ord("a") + best_shift))
        return "".join(key)

    @staticmethod
    def _column_score(column: list[str], shift: int, expected: list[float]) -> float:
        decrypted = [chr((ord(character) - ord("a") - shift) % 26 + ord("a")) for character in column]
        counts = Counter(decrypted)
        size = len(decrypted)
        return sum(
            (counts[chr(ord("a") + index)] - size * frequency / 100) ** 2
            / (size * frequency / 100)
            for index, frequency in enumerate(expected)
        )
