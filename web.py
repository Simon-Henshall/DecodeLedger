"""Small web interface for the multi-decoder."""

import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from decoder.engine import DecoderEngine


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


def analysis_payload(ciphertext: str) -> dict:
    analysis = DecoderEngine().analyze(ciphertext)
    return {
        "letter_count": analysis.letter_count,
        "index_of_coincidence": round(analysis.index_of_coincidence, 4),
        "chi_squared": round(analysis.chi_squared, 2),
        "entropy": round(analysis.entropy, 4),
        "entropy_band": analysis.entropy_band,
        "pipeline_route": analysis.pipeline_route,
        "character_set": analysis.character_set,
        "raw_character_set": analysis.raw_character_set,
        "likely_ciphers": list(analysis.likely_ciphers),
        "primary_cipher": analysis.primary_cipher,
        "hint": analysis.hint,
    }


class DecoderRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/decode":
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length))
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
    print("Multi-Decoder is running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()