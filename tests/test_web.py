from web import analysis_payload, decode_payload


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