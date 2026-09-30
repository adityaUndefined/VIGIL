from http.server import BaseHTTPRequestHandler
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import check_action

MAX_REQUEST_BYTES = 1_048_576

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
                raise ValueError("Request is too large (1 MB maximum).")

            raw = self.rfile.read(length)
            data = json.loads(raw or b"{}")

            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")

            content = data.get("content", "")
            action = data.get("action", "")

            if not isinstance(content, str):
                raise ValueError("content must be text.")
            if not isinstance(action, str):
                raise ValueError("action must be text.")
            if not content.strip():
                raise ValueError("Paste message or page content before analyzing.")

            result = check_action(content, action)

            self._json(200, result)

        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
