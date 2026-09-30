"""Vercel Vision endpoint: shapes analyze_vision() results for the frontend."""
from http.server import BaseHTTPRequestHandler
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vision_engine import analyze_vision  # noqa: E402

MAX_REQUEST_BYTES = 6_000_000


class handler(BaseHTTPRequestHandler):
    def _json(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_REQUEST_BYTES:
                raise ValueError("Vision payload is too large (6 MB maximum).")

            raw = self.rfile.read(length)
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")

            result = analyze_vision(data)
            self._json(200, result)

        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            # Never leak a stack trace to the client.
            self._json(500, {"error": "VIGIL Vision could not complete this analysis. Please try another screenshot."})
