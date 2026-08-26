# DecodeLedger

[![Tests](https://github.com/Simon-Henshall/DecodeLedger/actions/workflows/tests.yml/badge.svg)](https://github.com/Simon-Henshall/DecodeLedger/actions/workflows/tests.yml)
[![Test Coverage](https://codecov.io/gh/Simon-Henshall/DecodeLedger/branch/main/graph/badge.svg)](https://codecov.io/gh/Simon-Henshall/DecodeLedger)
[![Python Versions](https://shields.io)](https://github.com/Simon-Henshall/DecodeLedger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DecodeLedger is a Python toolkit for exploring unknown text. It tries a focused
set of classical ciphers, unwraps common encodings, and ranks candidate
plaintexts using lightweight English-language analysis.

This is an exploratory decoder, not a guarantee of the original message. Short
or unusual text can produce plausible-looking false positives, so treat the
ranking as a useful lead rather than proof.

## Features

- Tries Caesar, Atbash, Affine, Bacon, Rail Fence, Bifid, Hill, Scytale,
  Vigenere, Playfair, and Columnar Transposition ciphers.
- Detects and recursively unwraps hexadecimal, Base64, URL-safe Base64,
  binary, percent encoding, Base32, and Base85 before cipher cracking.
- Scores candidates from 0 to 1 using dictionary coverage, bigrams, trigrams,
  and normalised chi-square analysis.
- Exposes the same engine through a small command-line interface and a local
  browser interface with ciphertext analysis and ranked results.
- Uses only the Python standard library at runtime.

## Quick start

Requires Python 3.10 or newer.

```text
python main.py "Khoor, zruog!"
```

The default output is the highest-ranked candidate:

```text
[caesar] Hello, world! (score: 0.56)
```

To inspect more candidates, request a result count with `--top`. Add `--all`
to filter candidates by dictionary confidence; if no candidate passes the
threshold, the CLI falls back to the top-ranked results.

```text
python main.py "Khoor, zruog!" --all --top 5
python main.py "Khoor, zruog!" --all --top 5 --threshold 0.75
```

The threshold must be between 0 and 1, and `--top` must be at least 1.

## Browser interface

Start the local server from the repository root:

```text
python web.py
```

Open <http://127.0.0.1:8000> in a browser. The interface shows ranked decode
results alongside ciphertext statistics, likely ciphers, and any detected
encoding layers. The server binds to `127.0.0.1`, so it is intended for local
use.

## Development

Install the test dependency and run the suite:

```text
python -m pip install -r requirements.txt
python -m pytest
```

The engine is modular. To add a cipher, inherit from
`decoder.ciphers.base.Cipher`, implement `crack(ciphertext)`, and register an
instance in `decoder.engine.DEFAULT_CIPHERS`.

Custom Base64 alphabets are supported through
`recursive_unpeeler(..., custom_alphabet=...)`.

## Project layout

```text
main.py                 CLI entry point
web.py                  Local browser server and JSON API
decoder/ciphers/        Classical cipher implementations
decoder/intelligence/   Analysis, dictionary, frequency, and unpeeling logic
web/                    Browser interface assets
tests/                  Cipher, intelligence, and web tests
```

## License

See [LICENSE](LICENSE).
