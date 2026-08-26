"""Cipher pre-analysis using letter statistics and character-set clues."""

from collections import Counter
from dataclasses import dataclass

from .dictionary import dictionary_score
from .frequency import chi_squared_score, shannon_entropy


@dataclass(frozen=True)
class CipherAnalysis:
    letter_count: int
    index_of_coincidence: float
    chi_squared: float
    entropy: float
    entropy_band: str
    pipeline_route: str
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
    entropy = shannon_entropy(ciphertext)
    simple_substitution_confidence = max(
        dictionary_score(_shift_letters(ciphertext, shift)) for shift in range(26)
    ) if letters else 0.0
    atbash_confidence = dictionary_score(_atbash_letters(ciphertext)) if letters else 0.0

    if entropy < 3.0:
        entropy_band = "low"
        pipeline_route = "simple-cipher"
    elif 3.5 <= entropy <= 5.5:
        entropy_band = "natural"
        pipeline_route = "linguistic-region-coding"
    elif entropy > 6.5:
        entropy_band = "sky-high"
        pipeline_route = "brute-forcer-or-malware-triage"
    else:
        entropy_band = "middle"
        pipeline_route = "general-cipher-analysis"

    if character_set and set(character_set) <= {"a", "b"}:
        likely_ciphers = ("bacon",)
        hint = "Only A and B symbols detected: route directly to Bacon."
    elif atbash_confidence >= 0.5:
        likely_ciphers = ("atbash", "caesar", "affine", "rail fence", "scytale", "columnar transposition")
        hint = "Atbash produces recognizable English, suggesting a mirrored substitution."
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

    return CipherAnalysis(
        length, coincidence, chi_squared_score(letters), entropy, entropy_band,
        pipeline_route, character_set, likely_ciphers, hint,
    )


def _shift_letters(text: str, shift: int) -> str:
    return "".join(
        chr((ord(character.lower()) - ord("a") - shift) % 26 + ord("a"))
        if character.isascii() and character.isalpha() else character
        for character in text
    )


def _atbash_letters(text: str) -> str:
    return "".join(
        chr(ord("z") - (ord(character.lower()) - ord("a")))
        if character.isascii() and character.isalpha() else character
        for character in text
    )
