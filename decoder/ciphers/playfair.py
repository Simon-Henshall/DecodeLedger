"""Playfair cipher cracking with common keyword candidates."""

from .base import Cipher


class PlayfairCipher(Cipher):
    name = "playfair"
    common_keys = ("playfair example", "monarchy", "keyword", "secret", "cipher")

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if len(letters) < 2:
            return []
        if len(letters) % 2:
            letters = letters[:-1]
        return list(dict.fromkeys(self._decrypt(letters, key) for key in self.common_keys))

    @staticmethod
    def _square(key: str) -> tuple[str, dict[str, tuple[int, int]]]:
        alphabet = "abcdefghiklmnopqrstuvwxyz"
        sequence = ""
        for character in key.lower() + alphabet:
            if character == "j":
                character = "i"
            if character in alphabet and character not in sequence:
                sequence += character
        positions = {character: (index // 5, index % 5) for index, character in enumerate(sequence)}
        return sequence, positions

    @classmethod
    def _decrypt(cls, text: str, key: str) -> str:
        square, positions = cls._square(key)
        plaintext = []
        for index in range(0, len(text), 2):
            first, second = text[index : index + 2].replace("j", "i")
            first_row, first_column = positions[first]
            second_row, second_column = positions[second]
            if first_row == second_row:
                plaintext.extend((square[first_row * 5 + (first_column - 1) % 5],
                                  square[second_row * 5 + (second_column - 1) % 5]))
            elif first_column == second_column:
                plaintext.extend((square[((first_row - 1) % 5) * 5 + first_column],
                                  square[((second_row - 1) % 5) * 5 + second_column]))
            else:
                plaintext.extend((square[first_row * 5 + second_column],
                                  square[second_row * 5 + first_column]))
        return "".join(plaintext)