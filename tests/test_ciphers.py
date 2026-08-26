from decoder.ciphers import AtbashCipher, CaesarCipher, VigenereCipher


def test_caesar_returns_all_shifts():
    assert "Hello world" in CaesarCipher().crack("Khoor zruog")
    assert len(CaesarCipher().crack("abc")) == 26


def test_atbash_preserves_case_and_punctuation():
    assert AtbashCipher().crack("Svool, Dliow!") == ["Hello, World!"]


def test_vigenere_tries_common_key():
    assert "Attack at dawn" in VigenereCipher().crack("Lxfopv ef rnhr")
