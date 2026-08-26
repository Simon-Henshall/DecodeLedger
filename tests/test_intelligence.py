from decoder.engine import DecoderEngine
from decoder.intelligence.dictionary import dictionary_score, word_tokens
from decoder.intelligence.frequency import bigram_score, chi_squared_score, shannon_entropy, trigram_score
from decoder.intelligence.analysis import analyze_ciphertext
from main import build_parser


def test_frequency_score_is_finite_for_letters():
    assert chi_squared_score("this is an english sentence") < chi_squared_score("qzx qzx qzx qzx")


def test_ngram_scores_prefer_english_sequences():
    assert bigram_score("the quick brown fox") > bigram_score("qzx qzx qzx")
    assert trigram_score("the quick brown fox") > trigram_score("qzx qzx qzx")


def test_shannon_entropy_distinguishes_repetition_and_variety():
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcdefgh") == 3.0


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
    assert analysis.entropy_band == "low"
    assert analysis.pipeline_route == "simple-cipher"


def test_analysis_routes_natural_entropy_to_linguistic_pipeline():
    analysis = analyze_ciphertext("The quick brown fox jumps over the lazy dog")

    assert analysis.entropy_band == "natural"
    assert analysis.pipeline_route == "linguistic-region-coding"


def test_analysis_routes_high_entropy_to_triage_pipeline():
    analysis = analyze_ciphertext("".join(chr(0x400 + index) for index in range(128)))

    assert analysis.entropy_band == "sky-high"
    assert analysis.pipeline_route == "brute-forcer-or-malware-triage"


def test_analysis_identifies_low_ic_profile():
    analysis = analyze_ciphertext("Lxfopv ef rnhr")

    assert analysis.primary_cipher == "vigenere"
    assert analysis.chi_squared > 0


def test_analysis_uses_chi_square_to_refine_high_ic_profile():
    assert DecoderEngine().analyze("kdwaeanesztrardhkruatnkuu").primary_cipher == "bifid"
    assert DecoderEngine().analyze("wriorfeoeeesvelanadcedetc").primary_cipher == "scytale"


def test_cli_parser_exposes_readability_threshold():
    args = build_parser().parse_args(["ciphertext", "--all", "--threshold", "0.75"])

    assert args.all is True
    assert args.threshold == 0.75


def test_engine_accepts_parallel_worker_limit():
    engine = DecoderEngine(max_workers=2)

    assert engine.max_workers == 2
    assert engine.decode("Lxfopv ef rnhr")[0].plaintext == "Attack at dawn"
