# Multi-Decoder

A small Python command-line tool that tries several classical ciphers and ranks
the resulting plaintexts by how closely they resemble English.

## Installation

Python 3.10 or newer is recommended. The runtime uses only the standard library.
For development and tests, install the optional test dependency:

```text
python -m pip install -r requirements.txt
```

## Usage

Pass ciphertext as an argument:

```text
python main.py "Khoor, zruog!"
```

For a simple browser interface, start the local web server:

```text
python web.py
```

Then open <http://127.0.0.1:8000>.

The CLI prints the highest-ranked candidate by default. Use `--all` to inspect
only candidates that meet the dictionary-confidence threshold, and `--top N`
to limit the number shown:

```text
python main.py "Khoor, zruog!" --all --top 5
```

Adjust the readability threshold from 0 to 1 when needed:

```text
python main.py "Khoor, zruog!" --all --threshold 0.75
```

The package is intentionally modular. Add a cipher by inheriting from
`decoder.ciphers.base.Cipher`, implementing `crack(ciphertext)`, and registering
an instance in `decoder.engine.DEFAULT_CIPHERS`.

Candidates are ranked with a bounded English-confidence score from 0 to 1,
combining dictionary coverage, bigrams, trigrams, and normalised chi-square.

Before classical cracking, the engine performs a signature-gated first pass
for hexadecimal, Base64 and URL-safe Base64, binary, percent encoding, Base32,
and Base85. A recursive unpeeler follows useful decoded text through up to
four encoding layers; optional custom Base64 alphabets are supported through
`recursive_unpeeler(..., custom_alphabet=...)`.

## Project layout

- `main.py` - command-line entry point
- `decoder/ciphers/` - Affine, Atbash, Bacon, Bifid, Caesar, Hill, Vigenere, Playfair, Rail Fence, Scytale, and Columnar Transposition crackers
- `decoder/intelligence/` - frequency and dictionary scoring
- `tests/` - unit tests for the cipher and scoring layers
