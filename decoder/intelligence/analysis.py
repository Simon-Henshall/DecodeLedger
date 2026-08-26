"""Cipher pre-analysis using letter statistics and character-set clues."""

from collections import Counter
from dataclasses import dataclass

from .frequency import chi_squared_score
from .dictionary import dictionary_score


@dataclass(frozen=True)
class CipherAnalysis:
    letter_count: int
    index_of_coincidence: float
    chi_squared: float
    character_set: str
    likely_ciphers: tuple[str, ...]
    hint: str

    @property
    def primary_cipher(self) -> str:
        return self.likely_ciphers[0]


def analyze_ciphertext(ciphertext: str) -> CipherAnalysis:
    letters = "".join(character.lower() for character in ciphertext if character.isascii() and character.isalpha())
    counts = Counter(letters)
    length = len(letters)
    coincidence = (
        sum(count * (count - 1) for count in counts.values()) / (length * (length - 1))
        if length >= 2 else 0.0
    )
    character_set = "".join(sorted(set(letters)))
    simple_substitution_confidence = max(
        dictionary_score(_shift_letters(ciphertext, shift)) for shift in range(26)
    ) if letters else 0.0

    if character_set and set(character_set) <= {"a", "b"}:
        likely_ciphers = ("bacon",)
        hint = "Only A and B symbols detected: route directly to Bacon."
    elif simple_substitution_confidence >= 0.5:
        likely_ciphers = ("caesar", "atbash", "affine", "rail fence", "scytale", "columnar transposition")
        hint = "A Caesar-style shift produces recognizable English, suggesting simple substitution."
    elif coincidence >= 0.06 and chi_squared_score(letters) >= 50:
        likely_ciphers = ("bifid", "hill", "playfair", "vigenere", "caesar", "atbash", "affine")
        hint = "High IC with a high chi-square score suggests a digraph or polyalphabetic cipher."
    elif coincidence >= 0.06:
        likely_ciphers = ("scytale", "rail fence", "columnar transposition", "caesar", "atbash", "affine")
        hint = "High IC with a low chi-square score suggests transposition or simple substitution."
    elif coincidence <= 0.045:
        likely_ciphers = ("vigenere", "bifid", "hill", "playfair")
        hint = "Low IC suggests a polyalphabetic or digraph-based cipher."
    else:
        likely_ciphers = ("caesar", "vigenere", "bifid", "hill", "playfair")
        hint = "IC is inconclusive: comparing substitution, polyalphabetic, and digraph ciphers."

    return CipherAnalysis(length, coincidence, chi_squared_score(letters), character_set, likely_ciphers, hint)


def _shift_letters(text: str, shift: int) -> str:
    return "".join(
        chr((ord(character.lower()) - ord("a") - shift) % 26 + ord("a"))
        if character.isascii() and character.isalpha() else character
        for character in text
    )