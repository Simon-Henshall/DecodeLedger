"""Caesar cipher cracking."""

from .base import Cipher


class CaesarCipher(Cipher):
    name = "caesar"

    def crack(self, ciphertext: str) -> list[str]:
        return [self._shift(ciphertext, shift) for shift in range(26)]

    @staticmethod
    def _shift(text: str, shift: int) -> str:
        result = []
        for character in text:
            if character.isalpha() and character.isascii():
                base = ord("A") if character.isupper() else ord("a")
                result.append(chr((ord(character) - base - shift) % 26 + base))
            else:
                result.append(character)
        return "".join(result)
