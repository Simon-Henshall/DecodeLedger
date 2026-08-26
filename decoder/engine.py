"""Coordinate cipher cracking and English-language ranking."""

from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor
from math import exp
import os

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
from .intelligence import (
    CipherAnalysis,
    analyze_ciphertext,
    bigram_score,
    chi_squared_score,
    dictionary_score,
    trigram_score,
    recursive_unpeeler,
)


@dataclass(frozen=True)
class DecodeResult:
    cipher_name: str
    plaintext: str
    score: float
    dictionary_confidence: float


def _crack_cipher(arguments: tuple[Cipher, str]) -> tuple[str, list[str]]:
    cipher, ciphertext = arguments
    return cipher.name, cipher.crack(ciphertext)


def _analyze_text(text: str) -> CipherAnalysis:
    return analyze_ciphertext(text)


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
    def __init__(self, ciphers: tuple[Cipher, ...] = DEFAULT_CIPHERS, max_workers: int | None = None) -> None:
        self.ciphers = ciphers
        self.max_workers = max_workers

    def decode(self, ciphertext: str) -> list[DecodeResult]:
        results = []
        analysis = self.analyze(ciphertext)
        peeled_inputs = recursive_unpeeler(ciphertext)
        if len(peeled_inputs) > 1:
            return self._decode_peeled(peeled_inputs, analysis)
        return self._decode_text(ciphertext, analysis)

    def _decode_peeled(self, peeled_inputs: list[tuple[str, str]], analysis: CipherAnalysis) -> list[DecodeResult]:
        results = []
        analyses = self._analyze_peeled_inputs(peeled_inputs, analysis)
        for (encoding_chain, text), text_analysis in zip(peeled_inputs, analyses):
            for result in self._decode_text(text, text_analysis):
                name = f"{encoding_chain} -> {result.cipher_name}" if encoding_chain else result.cipher_name
                results.append(DecodeResult(name, result.plaintext, result.score, result.dictionary_confidence))
        return sorted(results, key=lambda result: result.score, reverse=True)

    def _analyze_peeled_inputs(
        self,
        peeled_inputs: list[tuple[str, str]],
        original_analysis: CipherAnalysis,
    ) -> list[CipherAnalysis]:
        if len(peeled_inputs) <= 1:
            return [original_analysis]
        analyses = [original_analysis]
        texts = [text for encoding_chain, text in peeled_inputs[1:]]
        worker_count = self.max_workers or min(len(texts), os.cpu_count() or 1)
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            analyses.extend(executor.map(_analyze_text, texts))
        return analyses

    def _decode_text(self, ciphertext: str, analysis: CipherAnalysis) -> list[DecodeResult]:
        results = []
        if analysis.primary_cipher == "bacon":
            ciphers = tuple(cipher for cipher in self.ciphers if cipher.name == "bacon")
        else:
            priority = {name: index for index, name in enumerate(analysis.likely_ciphers)}
            ciphers = tuple(sorted(self.ciphers, key=lambda cipher: priority.get(cipher.name, len(priority))))
        cipher_results = self._crack_in_parallel(ciphers, ciphertext)
        for cipher_name, plaintexts in cipher_results:
            for plaintext in plaintexts:
                word_confidence = dictionary_score(plaintext)
                bigram_confidence = bigram_score(plaintext)
                trigram_confidence = trigram_score(plaintext)
                chi_square = chi_squared_score(plaintext)
                chi_confidence = 0.0 if chi_square == float("inf") else exp(-chi_square / 100)
                reliability = min(1.0, sum(character.isascii() and character.isalpha() for character in plaintext) / 20)
                word_confidence = _reliable_confidence(word_confidence, reliability)
                bigram_confidence = _reliable_confidence(bigram_confidence, reliability)
                trigram_confidence = _reliable_confidence(trigram_confidence, reliability)
                chi_confidence = _reliable_confidence(chi_confidence, reliability)
                score = (
                    word_confidence * 0.45
                    + bigram_confidence * 0.20
                    + trigram_confidence * 0.20
                    + chi_confidence * 0.15
                )
                results.append(DecodeResult(cipher_name, plaintext, score, word_confidence))
        if analysis.primary_cipher in {"bifid", "hill", "playfair", "scytale", "rail fence", "columnar transposition"}:
            priority = {name: index for index, name in enumerate(analysis.likely_ciphers)}
            return sorted(results, key=lambda result: (priority.get(result.cipher_name, len(priority)), -result.score))
        return sorted(results, key=lambda result: result.score, reverse=True)

    def _crack_in_parallel(self, ciphers: tuple[Cipher, ...], ciphertext: str) -> list[tuple[str, list[str]]]:
        if len(ciphers) <= 1:
            return [_crack_cipher((cipher, ciphertext)) for cipher in ciphers]

        worker_count = self.max_workers or min(len(ciphers), os.cpu_count() or 1)
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            return list(executor.map(_crack_cipher, ((cipher, ciphertext) for cipher in ciphers)))

    @staticmethod
    def analyze(ciphertext: str) -> CipherAnalysis:
        return analyze_ciphertext(ciphertext)


def _reliable_confidence(value: float, reliability: float) -> float:
    """Shrink short-sample evidence toward neutral confidence."""
    return 0.5 + (value - 0.5) * reliability
