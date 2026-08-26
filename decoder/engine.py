"""Coordinate cipher cracking and English-language ranking."""

from dataclasses import dataclass

from .ciphers import (
    AffineCipher,
    AtbashCipher,
    BifidCipher,
    BaconCipher,
    CaesarCipher,
    ColumnarTranspositionCipher,
    PlayfairCipher,
    RailFenceCipher,
    VigenereCipher,
)
from .ciphers.base import Cipher
from .intelligence import chi_squared_score, dictionary_score


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
    VigenereCipher(),
    PlayfairCipher(),
    ColumnarTranspositionCipher(),
)


class DecoderEngine:
    def __init__(self, ciphers: tuple[Cipher, ...] = DEFAULT_CIPHERS) -> None:
        self.ciphers = ciphers

    def decode(self, ciphertext: str) -> list[DecodeResult]:
        results = []
        for cipher in self.ciphers:
            for plaintext in cipher.crack(ciphertext):
                word_confidence = dictionary_score(plaintext)
                score = chi_squared_score(plaintext) - word_confidence * 20
                results.append(DecodeResult(cipher.name, plaintext, score, word_confidence))
        return sorted(results, key=lambda result: result.score)
