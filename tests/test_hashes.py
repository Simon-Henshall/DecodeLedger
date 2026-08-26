from decoder.hashes import (
    Blake2BHash,
    Blake2SHash,
    HashAlgorithm,
    MD5Hash,
    NTLMHash,
    SHA1Hash,
    SHA224Hash,
    SHA256Hash,
    SHA384Hash,
    SHA512Hash,
    SHA3224Hash,
    SHA3256Hash,
    SHA3384Hash,
    SHA3512Hash,
)


def test_md5_name_and_digest_size():
    assert MD5Hash().name == "md5"
    assert MD5Hash().digest_sizes == (32,)


def test_sha1_name_and_digest_size():
    assert SHA1Hash().name == "sha1"
    assert SHA1Hash().digest_sizes == (40,)


def test_sha224_name_and_digest_size():
    assert SHA224Hash().name == "sha224"
    assert SHA224Hash().digest_sizes == (56,)


def test_sha256_name_and_digest_size():
    assert SHA256Hash().name == "sha256"
    assert SHA256Hash().digest_sizes == (64,)


def test_sha384_name_and_digest_size():
    assert SHA384Hash().name == "sha384"
    assert SHA384Hash().digest_sizes == (96,)


def test_sha512_name_and_digest_size():
    assert SHA512Hash().name == "sha512"
    assert SHA512Hash().digest_sizes == (128,)


def test_sha3_family_names_and_digest_sizes():
    assert SHA3224Hash().name == "sha3_224" and SHA3224Hash().digest_sizes == (56,)
    assert SHA3256Hash().name == "sha3_256" and SHA3256Hash().digest_sizes == (64,)
    assert SHA3384Hash().name == "sha3_384" and SHA3384Hash().digest_sizes == (96,)
    assert SHA3512Hash().name == "sha3_512" and SHA3512Hash().digest_sizes == (128,)


def test_blake2_family_names_and_digest_sizes():
    assert Blake2SHash().name == "blake2s" and Blake2SHash().digest_sizes == (64,)
    assert Blake2BHash().name == "blake2b" and Blake2BHash().digest_sizes == (128,)


def test_ntlm_name_and_digest_size():
    assert NTLMHash().name == "ntlm"
    assert NTLMHash().digest_sizes == (32,)


def test_md5_produces_expected_hex_digest():
    assert MD5Hash().hash_text("hello") == "5d41402abc4b2a76b9719d911017c592"


def test_sha256_produces_expected_hex_digest():
    assert SHA256Hash().hash_text("hello") == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e"
        "1b161e5c1fa7425e73043362938b9824"
    )


def test_standard_sha_family_produces_expected_hex_digests():
    assert SHA1Hash().hash_text("hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert SHA224Hash().hash_text("hello") == "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
    assert SHA384Hash().hash_text("hello") == (
        "59e1748777448c69de6b800d7a33bbfb"
        "9ff1b463e44354c3553bcdb9c666fa90"
        "125a3c79f90397bdf5f6a13de828684f"
    )
    assert SHA512Hash().hash_text("hello") == (
        "9b71d224bd62f3785d96d46ad3ea3d73"
        "319bfbc2890caadae2dff72519673ca72"
        "323c3d99ba5c11d7c7acc6e14b8c5da0c"
        "4663475c2e5c3adef46f73bcdec043"
    )


def test_sha3_family_produces_expected_hex_digests():
    assert SHA3224Hash().hash_text("hello") == "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81"
    assert SHA3256Hash().hash_text("hello") == "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
    assert SHA3384Hash().hash_text("hello") == (
        "720aea11019ef06440fbf05d87aa2468"
        "0a2153df3907b23631e7177ce620fa13"
        "30ff07c0fddee54699a4c3ee0ee9d887"
    )
    assert SHA3512Hash().hash_text("hello") == (
        "75d527c368f2efe848ecf6b073a36767"
        "800805e9eef2b1857d5f984f036eb6df"
        "891d75f72d9b154518c1cd58835286d1"
        "da9a38deba3de98b5a53e5ed78a84976"
    )


def test_blake2_family_produces_expected_hex_digests():
    assert Blake2SHash().hash_text("hello") == "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25"
    assert Blake2BHash().hash_text("hello") == (
        "e4cfa39a3d37be31c59609e807970799"
        "caa68a19bfaa15135f165085e01d41a6"
        "5ba1e1b146aeb6bd0092b49eac214c10"
        "3ccfa3a365954bbbe52f74a2b3620c94"
    )


def test_ntlm_produces_expected_hex_digest():
    assert NTLMHash().hash_text("hello") == "066ddfd4ef0e9cd7c256fe77191ef43c"
    assert NTLMHash().hash_text("Password") == "a4f49c406510bdcab6824ee7c30fd852"


ALL_ALGORITHMS: tuple[HashAlgorithm, ...] = (
    MD5Hash(),
    NTLMHash(),
    SHA1Hash(),
    SHA224Hash(),
    SHA256Hash(),
    SHA384Hash(),
    SHA512Hash(),
    SHA3224Hash(),
    SHA3256Hash(),
    SHA3384Hash(),
    SHA3512Hash(),
    Blake2SHash(),
    Blake2BHash(),
)


def test_hex_digest_lengths_match_digest_sizes():
    for text in ["", "a", "hello world", "Attack at dawn"]:
        for algorithm in ALL_ALGORITHMS:
            assert len(algorithm.hash_text(text)) in algorithm.digest_sizes


def test_hashing_is_deterministic_and_case_sensitive():
    for algorithm in ALL_ALGORITHMS:
        assert algorithm.hash_text("Hello") == algorithm.hash_text("Hello")
        assert algorithm.hash_text("Hello") != algorithm.hash_text("hello")