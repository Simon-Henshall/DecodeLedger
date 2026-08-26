"""Lightweight English word verification."""

import re

COMMON_WORDS = frozenset(
    "a an and are as at be by can for from has have he her his i if in is it "
    "me my not of on one or our she that the their them there they this to was "
    "we were what when where which who will with you your hello world secret "
    "attack message meet dawn project decode cipher text key quick brown fox "
    "over lazy dog"
    .split()
)


def word_tokens(text: str) -> list[str]:
    """Extract alphabetic words in lowercase."""
    return re.findall(r"[a-z]+", text.lower())


def dictionary_score(text: str) -> float:
    """Return the proportion of tokens found in the common-word set."""
    words = word_tokens(text)
    if not words:
        return 0.0
    return sum(word in COMMON_WORDS for word in words) / len(words)
