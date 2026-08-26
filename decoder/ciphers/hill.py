"""Hill cipher cracking with common invertible 2x2 keys."""

from .base import Cipher

class HillCipher(Cipher):
    name = "hill"
    common_keys = (
        ((3, 3), (2, 5)),
        ((5, 8), (17, 3)),
        ((11, 8), (3, 7)),
        ((9, 4), (5, 7)),
    )

    def crack(self, ciphertext: str) -> list[str]:
        letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
        if len(letters) < 2:
            return []
        letters = letters[: len(letters) // 2 * 2]
        candidates = [self._decrypt(letters, key) for key in self.common_keys if self._inverse(key) is not None]
        return list(dict.fromkeys(candidates))

    @classmethod
    def _decrypt(cls, text: str, key: tuple[tuple[int, int], tuple[int, int]]) -> str:
        inverse = cls._inverse(key)
        if inverse is None:
            return ""
        plaintext = []
        for index in range(0, len(text), 2):
            first = ord(text[index]) - ord("a")
            second = ord(text[index + 1]) - ord("a")
            plaintext.append(chr(ord("a") + (inverse[0][0] * first + inverse[0][1] * second) % 26))
            plaintext.append(chr(ord("a") + (inverse[1][0] * first + inverse[1][1] * second) % 26))
        return "".join(plaintext)

    @staticmethod
    def _inverse(key: tuple[tuple[int, int], tuple[int, int]]) -> tuple[tuple[int, int], tuple[int, int]] | None:
        (top_left, top_right), (bottom_left, bottom_right) = key
        determinant = (top_left * bottom_right - top_right * bottom_left) % 26
        inverse_determinant = next((value for value in range(26) if determinant * value % 26 == 1), None)
        if inverse_determinant is None:
            return None
        return (
            (bottom_right * inverse_determinant % 26, -top_right * inverse_determinant % 26),
            (-bottom_left * inverse_determinant % 26, top_left * inverse_determinant % 26),
        )