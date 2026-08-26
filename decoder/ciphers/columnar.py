"""Columnar transposition cipher cracking with common keyword candidates."""

from .base import Cipher


class ColumnarTranspositionCipher(Cipher):
    name = "columnar transposition"
    common_keys = ("zebras", "keyword", "transposition", "secret", "cipher")

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if not letters:
            return []
        return list(dict.fromkeys(self._decrypt(letters, key) for key in self.common_keys))

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        column_count = len(key)
        row_count, remainder = divmod(len(text), column_count)
        column_lengths = [row_count + (index < remainder) for index in range(column_count)]
        columns = [""] * column_count
        offset = 0
        for column in sorted(range(column_count), key=lambda index: (key[index], index)):
            length = column_lengths[column]
            columns[column] = text[offset : offset + length]
            offset += length
        return "".join(columns[column][row] for row in range(row_count + 1) for column in range(column_count)
                       if row < len(columns[column]))