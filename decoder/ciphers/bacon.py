"""Bacon cipher cracking for groups of five binary letters."""

from .base import Cipher


class BaconCipher(Cipher):
    name = "bacon"

    def crack(self, ciphertext: str) -> list[str]:
        symbols = "".join(character.lower() for character in ciphertext if character.lower() in "ab")
        if len(symbols) < 5:
            return []
        symbols = symbols[: len(symbols) // 5 * 5]
        return [self._decode(symbols)]

    @staticmethod
    def _decode(symbols: str) -> str:
        alphabet = "abcdefghiklmnopqrstuwxyz"
        plaintext = []
        for index in range(0, len(symbols), 5):
            value = int(symbols[index : index + 5].replace("a", "0").replace("b", "1"), 2)
            plaintext.append(alphabet[value] if value < len(alphabet) else "?")
        return "".join(plaintext)