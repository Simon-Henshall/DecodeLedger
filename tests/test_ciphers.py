from decoder.ciphers import (
    AffineCipher,
    AtbashCipher,
    BaconCipher,
    CaesarCipher,
    ColumnarTranspositionCipher,
    PlayfairCipher,
    VigenereCipher,
)


def test_caesar_returns_all_shifts():
    assert "Hello world" in CaesarCipher().crack("Khoor zruog")
    assert len(CaesarCipher().crack("abc")) == 26


def test_affine_tries_all_valid_keys():
    assert "Affine cipher" in AffineCipher().crack("Ihhwvc swfrcp")
    assert len(AffineCipher().crack("abc")) == 312


def test_atbash_preserves_case_and_punctuation():
    assert AtbashCipher().crack("Svool, Dliow!") == ["Hello, World!"]


def test_vigenere_tries_common_key():
    assert "Attack at dawn" in VigenereCipher().crack("Lxfopv ef rnhr")


def test_bacon_decodes_binary_groups():
    assert BaconCipher().crack("aabbb aabaa ababa ababa abbab") == ["hello"]


def test_playfair_tries_common_key():
    ciphertext = "BMODZBXDNABEKUDMUIXMMOUVIF"

    assert "hidethegoldinthetrexestump" in PlayfairCipher().crack(ciphertext)


def test_columnar_transposition_tries_common_key():
    ciphertext = "EVLNEACDTKESEAQROFOJDEECUWIREE"

    assert any(candidate.startswith("wearediscoveredfleeatonce")
               for candidate in ColumnarTranspositionCipher().crack(ciphertext))
