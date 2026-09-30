from http.server import BaseHTTPRequestHandler
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import guard_action

MAX_REQUEST_BYTES = 1_048_576
KNOWN_ACTIONS = {"navigate", "send_private_data", "send_credentials", "make_payment", "summarize", "read_page"}


class handler(BaseHTTPRequestHandler):
    def _json(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

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
            if not isinstance(content, str) or not content.strip():
                raise ValueError("content must be a non-empty string.")
            action = data.get("action", "")
            if not isinstance(action, str) or not action.strip():
                raise ValueError("action must be a non-empty string.")
            agent_id = data.get("agent_id", "")
            if not isinstance(agent_id, str):
                raise ValueError("agent_id must be a string.")

            # Fail closed on unknown actions without revealing internals.
            if action.strip().lower() not in KNOWN_ACTIONS:
                self._json(200, {
                    "decision": "DENY",
                    "allowed": False,
                    "machine_tag": "UNKNOWN_ACTION",
                    "reason": "Unknown action; the guard fails closed.",
                })
                return

            self._json(200, guard_action(content, action, agent_id))

        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            self._json(500, {"error": "VIGIL could not evaluate this action."})
