from http.server import BaseHTTPRequestHandler
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import LLM_CONFIG


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Availability is probed by the long-lived local server; serverless
        # functions report the configured provider/model without a cold
        # network probe per request.
        body = json.dumps({
            "status": "offline",
            "model": LLM_CONFIG["model"],
            "provider": LLM_CONFIG["provider"],
            "models": [],
            "verification": {
                "status": "not_run",
                "checked": 0,
                "verified": 0,
                "rejected": 0
            }
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
