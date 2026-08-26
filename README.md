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
every candidate and `--top N` to limit the number shown:

```text
python main.py "Khoor, zruog!" --all --top 5
```

The package is intentionally modular. Add a cipher by inheriting from
`decoder.ciphers.base.Cipher`, implementing `crack(ciphertext)`, and registering
an instance in `decoder.engine.DEFAULT_CIPHERS`.

## Project layout

- `main.py` - command-line entry point
- `decoder/ciphers/` - Affine, Atbash, Bacon, Bifid, Caesar, Vigenere, Playfair, Rail Fence, and Columnar Transposition crackers
- `decoder/intelligence/` - frequency and dictionary scoring
- `tests/` - unit tests for the cipher and scoring layers
