"""Loopback-only web server for VeilGuard Audit."""

import argparse
import json
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from integrations import ask_ollama, run_slither
from scanner import scan_source

WEB_DIR = Path(__file__).parent / "web"
MAX_REQUEST_BYTES = 512 * 1024
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Never log request bodies or submitted source.
        pass

    def _headers(self, status: int, content_type: str, length: int):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _request_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        if host not in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"):
            self._json(403, {"error": "invalid host"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"):
            self._json(403, {"error": "invalid origin"})
            return False
        return True

    def do_GET(self):
        if not self._request_allowed():
            return
        path = urlsplit(self.path).path
        if path == "/api/status":
            self._json(200, {"slither": bool(shutil.which("slither")), "ollama_endpoint": "http://127.0.0.1:11434", "ai_mode": "opt-in"})
            return
        asset = ASSETS.get(path)
        if not asset:
            self._json(404, {"error": "not found"})
            return
        file_name, content_type = asset
        try:
            body = (WEB_DIR / file_name).read_bytes()
        except OSError:
            self._json(500, {"error": "asset unavailable"})
            return
        self._headers(200, content_type, len(body))
        self.wfile.write(body)

    def do_POST(self):
        if not self._request_allowed():
            return
        path = urlsplit(self.path).path
        if path not in ("/api/scan", "/api/ai"):
            self._json(404, {"error": "not found"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._json(400, {"error": "Content-Type must be application/json"})
            return
        length_text = self.headers.get("Content-Length", "")
        if len(length_text) > 10 or not length_text.isascii() or not length_text.isdecimal():
            self._json(400, {"error": "Content-Length required"})
            return
        length = int(length_text)
        if length > MAX_REQUEST_BYTES:
            self._json(413, {"error": "request exceeds 512 KiB"})
            return
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("request must be a JSON object")
            source = data.get("source")
            findings = scan_source(source)
            if path == "/api/scan":
                result = {"findings": findings, "slither": {"status": "skipped", "findings": []}}
                if data.get("with_slither") is True:
                    result["slither"] = run_slither(source)
                self._json(200, result)
            else:
                model = data.get("model", "qwen2.5-coder:7b")
                self._json(200, {"review": ask_ollama(source, findings, model), "model": model})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            self._json(400, {"error": str(exc)[:160]})
        except RuntimeError as exc:
            self._json(503, {"error": str(exc)[:200]})


def create_server(host="127.0.0.1", port=8765):
    if host != "127.0.0.1":
        raise ValueError("server must bind to loopback 127.0.0.1")
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run VeilGuard Audit locally")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with create_server(port=args.port) as httpd:
        print(f"VeilGuard Audit: http://127.0.0.1:{httpd.server_port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
