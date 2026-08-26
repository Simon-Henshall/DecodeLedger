from decoder.hashes import MD5Hash, SHA256Hash


def test_md5_name_and_digest_size():
    assert MD5Hash().name == "md5"
    assert MD5Hash().digest_sizes == (32,)


def test_sha256_name_and_digest_size():
    assert SHA256Hash().name == "sha256"
    assert SHA256Hash().digest_sizes == (64,)


def test_md5_produces_expected_hex_digest():
    assert MD5Hash().hash_text("hello") == "5d41402abc4b2a76b9719d911017c592"


def test_sha256_produces_expected_hex_digest():
    assert SHA256Hash().hash_text("hello") == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e"
        "1b161e5c1fa7425e73043362938b9824"
    )


def test_hex_digest_lengths_match_digest_sizes():
    for text in ["", "a", "hello world", "Attack at dawn"]:
        assert len(MD5Hash().hash_text(text)) in MD5Hash().digest_sizes
        assert len(SHA256Hash().hash_text(text)) in SHA256Hash().digest_sizes


def test_hashing_is_deterministic_and_case_sensitive():
    hash_algorithm = SHA256Hash()
    assert hash_algorithm.hash_text("Hello") == hash_algorithm.hash_text("Hello")
    assert hash_algorithm.hash_text("Hello") != hash_algorithm.hash_text("hello")