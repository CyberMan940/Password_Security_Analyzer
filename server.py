from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from analyzer import analyze_password

MAX_BODY_BYTES = 4_096

class AnalysisRequestHandler(BaseHTTPRequestHandler):
    server_version = "PasswordSecurityAnalyzer/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        body = json.dumps(payload).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            self._send_json(404, {"error": "not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            content_length = -1
        if content_length < 0 or content_length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "request body is too large"})
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
            password = payload["password"]
            if not isinstance(password, str):
                raise ValueError
            result = analyze_password(password)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            self._send_json(400, {"error": "expected JSON with a string password"})
            return

        self._send_json(200, result.to_dict())


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), AnalysisRequestHandler)
    print(f"Password Analyzer API running at http://{host}:{port}")
    print("Endpoints: GET /health, POST /api/analyze")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()