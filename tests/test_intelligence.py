from decoder.engine import DecoderEngine
from decoder.intelligence.dictionary import dictionary_score, word_tokens
from decoder.intelligence.frequency import chi_squared_score
from decoder.intelligence.analysis import analyze_ciphertext


def test_frequency_score_is_finite_for_letters():
    assert chi_squared_score("this is an english sentence") < chi_squared_score("qzx qzx qzx qzx")


def test_dictionary_scores_known_words():
    assert word_tokens("Hello, world!") == ["hello", "world"]
    assert dictionary_score("hello world") == 1.0
    assert dictionary_score("hello qzx") == 0.5


def test_engine_ranks_caesar_plaintext_highest():
    result = DecoderEngine().decode("Khoor zruog")[0]
    assert result.plaintext == "Hello world"
    assert result.cipher_name == "caesar"


def test_engine_prefers_dictionary_confidence_for_vigenere():
    result = DecoderEngine().decode("Lxfopv ef rnhr")[0]

    assert result.plaintext == "Attack at dawn"
    assert result.cipher_name == "vigenere"


def test_analysis_routes_ab_input_to_bacon():
    analysis = analyze_ciphertext("aabbb aabaa ababa ababa abbab")

    assert analysis.primary_cipher == "bacon"
    assert analysis.index_of_coincidence > 0
    assert "A and B" in analysis.hint


def test_analysis_identifies_low_ic_profile():
    analysis = analyze_ciphertext("Lxfopv ef rnhr")

    assert analysis.primary_cipher == "vigenere"
    assert analysis.chi_squared > 0


def test_analysis_uses_chi_square_to_refine_high_ic_profile():
    assert DecoderEngine().analyze("kdwaeanesztrardhkruatnkuu").primary_cipher == "bifid"
    assert DecoderEngine().analyze("wriorfeoeeesvelanadcedetc").primary_cipher == "scytale"
