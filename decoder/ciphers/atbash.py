"""Atbash cipher cracking."""

from .base import Cipher


class AtbashCipher(Cipher):
    name = "atbash"

    def crack(self, ciphertext: str) -> list[str]:
        plaintext = []
        for character in ciphertext:
            if character.isalpha() and character.isascii():
                base = ord("A") if character.isupper() else ord("a")
                plaintext.append(chr(base + 25 - (ord(character) - base)))
            else:
                plaintext.append(character)
        return ["".join(plaintext)]
