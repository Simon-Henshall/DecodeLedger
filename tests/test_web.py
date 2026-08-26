from web import analysis_payload, crack_hash_payload, decode_payload


def test_web_decode_payload_returns_json_friendly_results():
    result = decode_payload({"ciphertext": "Khoor zruog", "limit": 1})[0]

    assert result["plaintext"] == "Hello world"
    assert result["cipher_name"] == "caesar"


def test_web_decode_payload_detects_atbash_result():
    result = decode_payload({"ciphertext": "Svool, Dliow!", "limit": 1})[0]

    assert result["plaintext"] == "Hello, World!"
    assert result["cipher_name"] == "atbash"


def test_web_decode_payload_returns_bacon_result():
    result = decode_payload({"ciphertext": "aabbb aabaa ababa ababa abbab", "limit": 5})[0]

    assert result["plaintext"] == "hello"
    assert result["cipher_name"] == "bacon"


def test_web_analysis_includes_cipher_hint():
    analysis = analysis_payload("aabbb aabaa ababa ababa abbab")

    assert analysis["primary_cipher"] == "bacon"
    assert analysis["likely_ciphers"] == ["bacon"]
    assert analysis["pipeline_route"] == "simple-cipher"
    assert " " in analysis["raw_character_set"]


def test_web_analysis_reports_recursive_encoding_layers():
    analysis = analysis_payload("48656c6c6f")

    assert "hex" in analysis["encoding_layers"]


def test_web_binary_input_returns_json_safe_analysis():
    analysis = analysis_payload("01001000 01100101 01101100 01101100 01101111")

    assert analysis["chi_squared"] is None
    assert analysis["encoding_layers"] == ["binary"]


def test_web_decode_prioritizes_predicted_transposition():
    result = decode_payload({"ciphertext": "wriorfeoeeesvelanadcedetc", "limit": 5})

    assert any(item["cipher_name"] == "scytale" and item["plaintext"] == "wearediscoveredfleeatonce" for item in result)


def test_web_decode_payload_rejects_blank_text():
    try:
        decode_payload({"ciphertext": "   "})
    except ValueError as error:
        assert str(error) == "Enter some text to decode."
    else:
        raise AssertionError("blank ciphertext should be rejected")


def test_web_crack_hash_recovers_dictionary_word():
    result = crack_hash_payload({"digest": "5d41402abc4b2a76b9719d911017c592", "algorithm": "md5"})

    assert result == [{"hash_name": "md5", "plaintext": "hello", "method": "dictionary"}]


def test_web_crack_hash_any_supported_algorithm():
    result = crack_hash_payload({"digest": "5d41402abc4b2a76b9719d911017c592", "algorithm": ""})

    assert result == [{"hash_name": "md5", "plaintext": "hello", "method": "dictionary"}]


def test_web_crack_hash_omitted_algorithm_defaults_to_all():
    result = crack_hash_payload({"digest": "5d41402abc4b2a76b9719d911017c592"})

    assert result == [{"hash_name": "md5", "plaintext": "hello", "method": "dictionary"}]


def test_web_crack_hash_rejects_blank_digest():
    try:
        crack_hash_payload({"digest": "   "})
    except ValueError as error:
        assert str(error) == "A hash digest is required to crack."
    else:
        raise AssertionError("blank digest should be rejected")


def test_web_crack_hash_rejects_unknown_algorithm():
    try:
        crack_hash_payload({"digest": "5d41402abc4b2a76b9719d911017c592", "algorithm": "des"})
    except ValueError as error:
        assert "Unsupported algorithm" in str(error)
    else:
        raise AssertionError("unknown algorithm should be rejected")