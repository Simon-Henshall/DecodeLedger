from main import build_parser

from decoder.hashattack import HashCracker
from decoder.hashes import MD5Hash, SHA256Hash


def test_dictionary_attack_recovers_common_word():
    result = HashCracker().crack(MD5Hash().hash_text("hello"))

    assert len(result) == 1
    assert result[0].plaintext == "hello"
    assert result[0].hash_name == "md5"
    assert result[0].method == "dictionary"


def test_brute_force_recovers_short_plaintext():
    result = HashCracker(max_length=2).crack(MD5Hash().hash_text("ab"))

    assert result[0].plaintext == "ab"
    assert result[0].method == "brute-force"


def test_brute_force_honors_max_length():
    result = HashCracker(max_length=1).crack(MD5Hash().hash_text("ab"))

    assert result == []


def test_only_matching_algorithm_is_attempted():
    digest = SHA256Hash().hash_text("hello")

    assert [result.hash_name for result in HashCracker().crack(digest)] == ["sha256"]


def test_attack_skips_wrong_length_digests():
    assert HashCracker(max_length=2).crack("zz") == []


def test_attack_returns_empty_when_no_match():
    assert HashCracker(max_length=4).crack(SHA256Hash().hash_text("qwerty")) == []


def test_cli_parser_exposes_crack_arguments():
    args = build_parser().parse_args(
        ["5d41402abc4b2a76b9719d911017c592", "--hash", "--algorithm", "md5", "--max-length", "3"]
    )

    assert args.hash is True
    assert args.algorithm == "md5"
    assert args.max_length == 3