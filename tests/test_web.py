from web import decode_payload


def test_web_decode_payload_returns_json_friendly_results():
    result = decode_payload({"ciphertext": "Khoor zruog", "limit": 1})[0]

    assert result["plaintext"] == "Hello world"
    assert result["cipher_name"] == "caesar"


def test_web_decode_payload_rejects_blank_text():
    try:
        decode_payload({"ciphertext": "   "})
    except ValueError as error:
        assert str(error) == "Enter some text to decode."
    else:
        raise AssertionError("blank ciphertext should be rejected")