"""Small web interface for DecodeLedger."""

import json
import math
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from decoder.engine import DecoderEngine
from decoder.hashattack import DEFAULT_HASHES, HashCracker
from decoder.intelligence import recursive_unpeeler


WEB_ROOT = Path(__file__).parent / "web"


def decode_payload(payload: dict) -> list[dict]:
    """Decode a request payload and return JSON-friendly results."""
    ciphertext = payload.get("ciphertext", "")
    if not isinstance(ciphertext, str) or not ciphertext.strip():
        raise ValueError("Enter some text to decode.")

    limit = payload.get("limit", 5)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
        raise ValueError("Result limit must be between 1 and 20.")

    return [
        {
            "cipher_name": result.cipher_name,
            "plaintext": result.plaintext,
            "score": round(result.score, 2),
            "dictionary_confidence": round(result.dictionary_confidence, 2),
        }
        for result in DecoderEngine().decode(ciphertext)[:limit]
    ]


def crack_hash_payload(payload: dict) -> list[dict]:
    """Run a dictionary/brute-force attack on a hash digest and return JSON-friendly results."""
    digest = payload.get("digest", "")
    if not isinstance(digest, str) or not digest.strip():
        raise ValueError("A hash digest is required to crack.")

    algorithm = payload.get("algorithm")
    supported = {hash_algorithm.name for hash_algorithm in DEFAULT_HASHES}
    if algorithm and algorithm not in supported:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from {sorted(supported)}.")
    if algorithm not in supported:
        algorithm = None

    max_length = payload.get("max_length", 4)
    if not isinstance(max_length, int) or isinstance(max_length, bool) or not 1 <= max_length <= 8:
        raise ValueError("Brute-force length must be between 1 and 8.")

    algorithms = DEFAULT_HASHES if algorithm is None else tuple(
        hash_algorithm for hash_algorithm in DEFAULT_HASHES if hash_algorithm.name == algorithm
    )
    return [
        {"hash_name": result.hash_name, "plaintext": result.plaintext, "method": result.method}
        for result in HashCracker(algorithms=algorithms, max_length=max_length).crack(digest)
    ]


def analysis_payload(ciphertext: str) -> dict:
    analysis = DecoderEngine().analyze(ciphertext)
    encoding_layers = [chain for chain, value in recursive_unpeeler(ciphertext) if chain]
    return {
        "letter_count": analysis.letter_count,
        "index_of_coincidence": round(analysis.index_of_coincidence, 4),
        "chi_squared": round(analysis.chi_squared, 2) if math.isfinite(analysis.chi_squared) else None,
        "entropy": round(analysis.entropy, 4),
        "entropy_band": analysis.entropy_band,
        "pipeline_route": analysis.pipeline_route,
        "character_set": analysis.character_set,
        "raw_character_set": analysis.raw_character_set,
        "encoding_layers": encoding_layers,
        "likely_ciphers": list(analysis.likely_ciphers),
        "primary_cipher": analysis.primary_cipher,
        "hint": analysis.hint,
    }


class DecoderRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/decode", "/api/hash-crack"}:
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length))
            if path == "/api/hash-crack":
                response = crack_hash_payload(payload)
            else:
                ciphertext = payload.get("ciphertext", "")
                response = {"analysis": analysis_payload(ciphertext), "results": decode_payload(payload)}
            status = 200
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            response = {"error": str(error)}
            status = 400

        body = json.dumps(response).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), DecoderRequestHandler)
    print("DecodeLedger is running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()