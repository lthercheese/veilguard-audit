import io
import json
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

from server import Handler, create_server


def request(method, path, data=None, content_type="application/json", length_override=None):
    payload = json.dumps(data).encode() if isinstance(data, dict) else (data or b"")
    handler = Handler.__new__(Handler)
    handler.path = path
    handler.command = method
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.headers = Message()
    handler.headers["Host"] = "127.0.0.1:8765"
    if method == "POST":
        handler.headers["Content-Type"] = content_type
        handler.headers["Content-Length"] = str(len(payload)) if length_override is None else length_override
    handler.rfile = io.BytesIO(payload)
    handler.wfile = io.BytesIO()
    handler.client_address = ("127.0.0.1", 45678)
    handler.server = SimpleNamespace(server_name="127.0.0.1", server_port=8765)
    handler.log_message = lambda *args: None
    getattr(handler, "do_" + method)()
    head, _, body = handler.wfile.getvalue().partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body) if body and b"application/json" in head.lower() else body


class ServerTests(unittest.TestCase):
    def test_scan_returns_line_finding_and_no_ai(self):
        with patch("server.ask_ollama", side_effect=AssertionError("AI called")):
            status, result = request("POST", "/api/scan", {"source": "contract A { function f() public { require(tx.origin == msg.sender); } }"})
        self.assertEqual(status, 200)
        self.assertEqual(result["findings"][0]["rule_id"], "tx-origin")
        self.assertEqual(result["findings"][0]["line"], 1)
        self.assertNotIn("ai", result)

    def test_ai_route_uses_local_adapter_only_on_request(self):
        with patch("server.ask_ollama", return_value="Review access control") as answer:
            status, result = request("POST", "/api/ai", {"source": "contract A {}", "model": "local-model"})
        self.assertEqual(status, 200)
        self.assertEqual(result["review"], "Review access control")
        self.assertEqual(answer.call_count, 1)

    def test_invalid_json_and_content_type_are_rejected(self):
        for payload, content_type in ((b"{oops", "application/json"), (b"source=x", "text/plain")):
            with self.subTest(payload=payload):
                status, _ = request("POST", "/api/scan", payload, content_type)
                self.assertEqual(status, 400)

    def test_malformed_length_and_deep_json_are_rejected(self):
        status, _ = request("POST", "/api/scan", b"{}", length_override="9" * 5000)
        self.assertEqual(status, 400)
        status, _ = request("POST", "/api/scan", ("[" * 1500 + "]" * 1500).encode())
        self.assertEqual(status, 400)

    def test_status_and_unknown_path(self):
        status_code, status = request("GET", "/api/status")
        self.assertEqual(status_code, 200)
        self.assertIn("slither", status)
        self.assertIn("ollama_endpoint", status)
        missing, _ = request("GET", "/private")
        self.assertEqual(missing, 404)

    def test_non_loopback_binding_is_refused(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            create_server(host="0.0.0.0", port=0)


if __name__ == "__main__":
    unittest.main()
