"""Rail Fence cipher cracking with common rail counts."""

from .base import Cipher


class RailFenceCipher(Cipher):
    name = "rail fence"

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if not letters:
            return []
        return list(dict.fromkeys(self._decrypt(letters, rails) for rails in range(2, min(10, len(letters)) + 1)))

    @staticmethod
    def _decrypt(text: str, rails: int) -> str:
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        rail_indexes = [pattern[index % len(pattern)] for index in range(len(text))]
        counts = [rail_indexes.count(rail) for rail in range(rails)]
        rail_text = []
        offset = 0
        for count in counts:
            rail_text.append(text[offset : offset + count])
            offset += count
        positions = [0] * rails
        plaintext = []
        for rail in rail_indexes:
            plaintext.append(rail_text[rail][positions[rail]])
            positions[rail] += 1
        return "".join(plaintext)