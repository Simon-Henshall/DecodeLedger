"""Command-line entry point for multi-decoder."""

import argparse

from decoder.engine import DecoderEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Try classical ciphers and rank English plaintexts.")
    parser.add_argument("ciphertext", help="text to decode")
    parser.add_argument("--all", action="store_true", help="show all ranked candidates")
    parser.add_argument("--top", type=int, default=1, help="number of candidates to show (default: 1)")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.top < 1:
        raise SystemExit("--top must be at least 1")

    results = DecoderEngine().decode(args.ciphertext)
    displayed = results[: args.top] if args.all else results[:1]
    for result in displayed:
        print(f"[{result.cipher_name}] {result.plaintext} (score: {result.score:.2f})")


if __name__ == "__main__":
    main()
