from decoder.engine import DecoderEngine
from decoder.intelligence.dictionary import dictionary_score, word_tokens
from decoder.intelligence.frequency import chi_squared_score


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
