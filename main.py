"""Command-line entry point for DecodeLedger."""

import argparse

from decoder.engine import DecoderEngine
from decoder.hashattack import DEFAULT_HASHES, HashCracker


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Try classical ciphers and rank English plaintexts, or crack hashes."
    )
    parser.add_argument("input", help="text to decode, or a hash digest when --hash is used")
    parser.add_argument("--all", action="store_true", help="show all ranked candidates")
    parser.add_argument("--top", type=int, default=1, help="number of candidates to show (default: 1)")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="minimum dictionary confidence for --all candidates (default: 0.5)",
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        help="treat the input as a hash digest and run a dictionary/brute-force attack",
    )
    parser.add_argument(
        "--algorithm",
        choices=[hash_algorithm.name for hash_algorithm in DEFAULT_HASHES],
        default=None,
        help="hash algorithm to try (default: try every supported algorithm)",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=4,
        help="maximum candidate length for the brute-force pass (default: 4)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.hash:
        main_crack(args)
    else:
        main_decode(args)


def main_decode(args: argparse.Namespace) -> None:
    if args.top < 1:
        raise SystemExit("--top must be at least 1")
    if not 0 <= args.threshold <= 1:
        raise SystemExit("--threshold must be between 0 and 1")

    results = DecoderEngine().decode(args.input)
    if args.all:
        readable = [result for result in results if result.dictionary_confidence >= args.threshold]
        displayed = (readable or results)[: args.top]
    else:
        displayed = results[:1]
    for result in displayed:
        print(f"[{result.cipher_name}] {result.plaintext} (score: {result.score:.2f})")


def main_crack(args: argparse.Namespace) -> None:
    if args.max_length < 1:
        raise SystemExit("--max-length must be at least 1")

    algorithms = DEFAULT_HASHES
    if args.algorithm:
        algorithms = tuple(
            hash_algorithm for hash_algorithm in DEFAULT_HASHES if hash_algorithm.name == args.algorithm
        )
    results = HashCracker(algorithms=algorithms, max_length=args.max_length).crack(args.input)
    if not results:
        print("No match found in the dictionary or brute-force space.")
        return
    for result in results:
        print(f"[{result.hash_name}] {result.plaintext} (via {result.method})")


if __name__ == "__main__":
    main()
