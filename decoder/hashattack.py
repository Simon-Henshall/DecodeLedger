"""Dictionary-attack and brute-force cracking of cryptographic hashes."""

import itertools
from dataclasses import dataclass

from .hashes import HashAlgorithm, MD5Hash, SHA256Hash
from .intelligence.dictionary import COMMON_WORDS


@dataclass(frozen=True)
class HashAttackResult:
    """A recovered plaintext for a given hash digest."""

    hash_name: str
    plaintext: str
    method: str


DEFAULT_HASHES: tuple[HashAlgorithm, ...] = (MD5Hash(), SHA256Hash())

# Lowercase alphabetical keyspace used when walking brute-force candidates.
DEFAULT_CHARACTERS = "abcdefghijklmnopqrstuvwxyz"
DEFAULT_MAX_LENGTH = 4


class HashCracker:
    """Try dictionary words, then brute-force combinations, against a digest."""

    def __init__(
        self,
        algorithms: tuple[HashAlgorithm, ...] = DEFAULT_HASHES,
        max_length: int = DEFAULT_MAX_LENGTH,
        characters: str = DEFAULT_CHARACTERS,
    ) -> None:
        self.algorithms = algorithms
        self.max_length = max_length
        self.characters = characters

    def crack(self, digest: str) -> list[HashAttackResult]:
        """Return plaintext candidates that hash to ``digest``."""
        normalized = digest.strip().lower()
        results = []
        for algorithm in self.algorithms:
            if len(normalized) not in algorithm.digest_sizes:
                continue
            results.extend(self._crack_algorithm(algorithm, normalized))
        return results

    def _crack_algorithm(self, algorithm: HashAlgorithm, digest: str) -> list[HashAttackResult]:
        for word in sorted(COMMON_WORDS, key=len):
            if algorithm.hash_text(word) == digest:
                return [HashAttackResult(algorithm.name, word, "dictionary")]
        for length in range(1, self.max_length + 1):
            for combination in itertools.product(self.characters, repeat=length):
                plaintext = "".join(combination)
                if algorithm.hash_text(plaintext) == digest:
                    return [HashAttackResult(algorithm.name, plaintext, "brute-force")]
        return []