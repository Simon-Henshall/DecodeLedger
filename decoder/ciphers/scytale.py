"""Scytale cipher cracking with common rod diameters."""

from .base import Cipher


class ScytaleCipher(Cipher):
    name = "scytale"

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if not letters:
            return []
        return list(dict.fromkeys(self._decrypt(letters, diameter)
                                 for diameter in range(2, min(10, len(letters)) + 1)))

    @staticmethod
    def _decrypt(text: str, diameter: int) -> str:
        column_count, remainder = divmod(len(text), diameter)
        row_lengths = [column_count + (row < remainder) for row in range(diameter)]
        rows = [""] * diameter
        offset = 0
        for row, length in enumerate(row_lengths):
            rows[row] = text[offset : offset + length]
            offset += length
        return "".join(rows[row][column] for column in range(column_count + 1)
                       for row in range(diameter) if column < len(rows[row]))