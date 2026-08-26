"""First-pass structural decoding for common text encodings."""

from base64 import a85decode, b16decode, b32decode, b64decode, urlsafe_b64decode
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class EncodingLayer:
    encoding: str
    value: str


def recursive_unpeeler(text: str, max_depth: int = 4, custom_alphabet: str | None = None) -> list[tuple[str, str]]:
    """Return the original text and unique recursively decoded variants."""
    results = [("", text)]
    queue = [("", text, 0)]
    seen = {text}
    while queue:
        chain, current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for encoding, decoded in _try_encodings(current, custom_alphabet):
            if decoded == current or not decoded or decoded in seen:
                continue
            seen.add(decoded)
            next_chain = f"{chain} -> {encoding}" if chain else encoding
            results.append((next_chain, decoded))
            queue.append((next_chain, decoded, depth + 1))
    return results


def _try_encodings(text: str, custom_alphabet: str | None = None) -> list[tuple[str, str]]:
    candidates = []
    compact = "".join(text.split())
    if _looks_like_hex(compact):
        _try_decode(candidates, "hex", lambda: b16decode(compact, casefold=True))
    if _looks_like_binary(compact):
        _try_decode(candidates, "binary", lambda: bytes(int(group, 2) for group in _binary_groups(text, compact)))
    if "%" in text and _looks_like_percent_encoding(text):
        _try_decode(candidates, "percent", lambda: unquote(text).encode("utf-8"))
    if _looks_like_base32(compact):
        _try_decode(candidates, "base32", lambda: b32decode(compact + "=" * (-len(compact) % 8), casefold=True))
    if _looks_like_base64(compact):
        _try_decode(candidates, "base64", lambda: b64decode(compact + "=" * (-len(compact) % 4), validate=True))
        _try_decode(candidates, "urlsafe base64", lambda: urlsafe_b64decode(compact + "=" * (-len(compact) % 4)))
        if custom_alphabet and len(custom_alphabet) == 64:
            standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            translated = compact.translate(str.maketrans(custom_alphabet, standard))
            _try_decode(candidates, "custom base64", lambda: b64decode(translated + "=" * (-len(translated) % 4), validate=True))
    if _looks_like_base85(text):
        _try_decode(candidates, "base85", lambda: a85decode(text.encode("ascii"), adobe=text.startswith("<~")))
    return candidates


def _try_decode(candidates: list[tuple[str, str]], name: str, decoder) -> None:
    try:
        decoded = decoder().decode("utf-8")
    except (ValueError, UnicodeDecodeError, TypeError):
        return
    if _is_useful_text(decoded):
        candidates.append((name, decoded))


def _groups(text: str, size: int) -> list[str]:
    return [text[index : index + size] for index in range(0, len(text), size)]


def _binary_groups(text: str, compact: str) -> list[str]:
    groups = text.split()
    return groups if groups and all(len(group) == 8 for group in groups) else _groups(compact, 8)


def _looks_like_hex(text: str) -> bool:
    return len(text) >= 4 and len(text) % 2 == 0 and all(character in "0123456789abcdefABCDEF" for character in text)


def _looks_like_binary(text: str) -> bool:
    return len(text) >= 8 and all(character in "01" for character in text) and len(text) % 8 == 0


def _looks_like_percent_encoding(text: str) -> bool:
    return any(text[index : index + 3].startswith("%") for index in range(len(text) - 2))


def _looks_like_base32(text: str) -> bool:
    return len(text) >= 8 and len(text) % 8 in (0, 2, 4, 5, 7) and all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for character in text.upper())


def _looks_like_base64(text: str) -> bool:
    return len(text) >= 8 and len(text) % 4 in (0, 2, 3) and all(character.isalnum() or character in "+/_-=" for character in text)


def _looks_like_base85(text: str) -> bool:
    return text.startswith("<~") and text.endswith("~>") or len(text) >= 5 and all(33 <= ord(character) <= 117 for character in text)


def _is_useful_text(text: str) -> bool:
    return any(character.isalnum() or character.isspace() for character in text)