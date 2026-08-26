"""English letter-frequency scoring."""

from collections import Counter
from math import log2
import string

ENGLISH_FREQUENCIES = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70,
    "f": 2.23, "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15,
    "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75, "o": 7.51,
    "p": 1.93, "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06,
    "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15, "y": 1.97,
    "z": 0.07,
}

COMMON_BIGRAMS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split()
)
COMMON_TRIGRAMS = frozenset(
    "the and ing her ere ent tha nth was eth for dth hat she ion tio ver est ers ati his all ith ted ter ers ate you ons ith one our out are rea eve con not but had with this ting ment".split()
)


def chi_squared_score(text: str) -> float:
    """Return the chi-squared distance from typical English frequencies."""
    letters = [character for character in text.lower() if character in string.ascii_lowercase]
    if not letters:
        return float("inf")

    counts = Counter(letters)
    length = len(letters)
    return sum(
        (counts[letter] - length * expected / 100) ** 2
        / (length * expected / 100)
        for letter, expected in ENGLISH_FREQUENCIES.items()
    )


def _ngram_score(text: str, n: int, common: frozenset[str]) -> float:
    letters = "".join(character for character in text.lower() if character in string.ascii_lowercase)
    if len(letters) < n:
        return 0.0
    ngrams = [letters[index : index + n] for index in range(len(letters) - n + 1)]
    return sum(ngram in common for ngram in ngrams) / len(ngrams)


def bigram_score(text: str) -> float:
    """Return the proportion of adjacent letter pairs common in English."""
    return _ngram_score(text, 2, COMMON_BIGRAMS)


def trigram_score(text: str) -> float:
    """Return the proportion of adjacent letter triplets common in English."""
    return _ngram_score(text, 3, COMMON_TRIGRAMS)


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy in bits per non-whitespace character."""
    symbols = [character for character in text if not character.isspace()]
    if not symbols:
        return 0.0
    counts = Counter(symbols)
    length = len(symbols)
    return -sum((count / length) * log2(count / length) for count in counts.values())
