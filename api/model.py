from http.server import BaseHTTPRequestHandler
import json
import os

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "status": "offline",
            "name": os.getenv("VIGIL_OLLAMA_MODEL", "qwen3.5:2b"),
            "signals_added": 0,
            "signals": [],
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
