"""Command-line entry point for DecodeLedger."""

import argparse

from decoder.engine import DecoderEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Try classical ciphers and rank English plaintexts.")
    parser.add_argument("ciphertext", help="text to decode")
    parser.add_argument("--all", action="store_true", help="show all ranked candidates")
    parser.add_argument("--top", type=int, default=1, help="number of candidates to show (default: 1)")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="minimum dictionary confidence for --all candidates (default: 0.5)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.top < 1:
        raise SystemExit("--top must be at least 1")
    if not 0 <= args.threshold <= 1:
        raise SystemExit("--threshold must be between 0 and 1")

    results = DecoderEngine().decode(args.ciphertext)
    if args.all:
        readable = [result for result in results if result.dictionary_confidence >= args.threshold]
        displayed = (readable or results)[: args.top]
    else:
        displayed = results[:1]
    for result in displayed:
        print(f"[{result.cipher_name}] {result.plaintext} (score: {result.score:.2f})")


if __name__ == "__main__":
    main()
