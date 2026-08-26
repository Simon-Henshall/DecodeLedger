"""Coordinate cipher cracking and English-language ranking."""

from dataclasses import dataclass

from .ciphers import (
    AffineCipher,
    AtbashCipher,
    BifidCipher,
    BaconCipher,
    CaesarCipher,
    ColumnarTranspositionCipher,
    HillCipher,
    PlayfairCipher,
    RailFenceCipher,
    ScytaleCipher,
    VigenereCipher,
)
from .ciphers.base import Cipher
from .intelligence import CipherAnalysis, analyze_ciphertext, chi_squared_score, dictionary_score


@dataclass(frozen=True)
class DecodeResult:
    cipher_name: str
    plaintext: str
    score: float
    dictionary_confidence: float


DEFAULT_CIPHERS: tuple[Cipher, ...] = (
    CaesarCipher(),
    AtbashCipher(),
    AffineCipher(),
    BaconCipher(),
    RailFenceCipher(),
    BifidCipher(),
    HillCipher(),
    ScytaleCipher(),
    VigenereCipher(),
    PlayfairCipher(),
    ColumnarTranspositionCipher(),
)


class DecoderEngine:
    def __init__(self, ciphers: tuple[Cipher, ...] = DEFAULT_CIPHERS) -> None:
        self.ciphers = ciphers

    def decode(self, ciphertext: str) -> list[DecodeResult]:
        results = []
        analysis = self.analyze(ciphertext)
        if analysis.primary_cipher == "bacon":
            ciphers = tuple(cipher for cipher in self.ciphers if cipher.name == "bacon")
        else:
            priority = {name: index for index, name in enumerate(analysis.likely_ciphers)}
            ciphers = tuple(sorted(self.ciphers, key=lambda cipher: priority.get(cipher.name, len(priority))))
        for cipher in ciphers:
            for plaintext in cipher.crack(ciphertext):
                word_confidence = dictionary_score(plaintext)
                score = chi_squared_score(plaintext) - word_confidence * 50
                results.append(DecodeResult(cipher.name, plaintext, score, word_confidence))
        if analysis.primary_cipher in {"bifid", "hill", "playfair", "scytale", "rail fence", "columnar transposition"}:
            priority = {name: index for index, name in enumerate(analysis.likely_ciphers)}
            return sorted(results, key=lambda result: (priority.get(result.cipher_name, len(priority)), result.score))
        return sorted(results, key=lambda result: result.score)

    @staticmethod
    def analyze(ciphertext: str) -> CipherAnalysis:
        return analyze_ciphertext(ciphertext)
