import json
import unittest
from pathlib import Path
from unittest.mock import patch

from integrations import ask_ollama, run_slither


class IntegrationsTests(unittest.TestCase):
    def test_slither_unavailable_is_visible(self):
        with patch("integrations.shutil.which", return_value=None):
            result = run_slither("contract A {}")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["findings"], [])

    def test_slither_detector_is_mapped_with_line(self):
        output = {"success": True, "results": {"detectors": [{"check": "reentrancy-eth", "impact": "High", "confidence": "Medium", "description": "External call before write", "elements": [{"source_mapping": {"lines": [7]}}]}]}}
        class Process:
            returncode = 0
            stdout = json.dumps(output)
            stderr = ""
        with patch("integrations.shutil.which", return_value="slither"), patch("integrations.subprocess.run", return_value=Process()), patch("integrations.tempfile.tempdir", str(Path(__file__).parents[1])):
            result = run_slither("contract A {}")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"][0]["line"], 7)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_ollama_answer_is_separate_text(self):
        class Response:
            status = 200
            def read(self, size):
                return json.dumps({"message": {"content": "Review the withdrawal state update."}}).encode()
        class Connection:
            def __init__(self, *args, **kwargs):
                self.sent = None
            def request(self, method, path, body, headers):
                self.sent = (method, path, body, headers)
            def getresponse(self):
                return Response()
            def close(self):
                pass
        connection = Connection()
        with patch("integrations.HTTPConnection", return_value=connection) as opened:
            answer = ask_ollama("contract A {}", [], "local-model")
        self.assertIn("withdrawal", answer)
        self.assertEqual(opened.call_args.args[:2], ("127.0.0.1", 11434))
        self.assertEqual(connection.sent[:2], ("POST", "/api/chat"))
        self.assertEqual(json.loads(connection.sent[2])["stream"], False)

    def test_model_name_is_restricted(self):
        with self.assertRaisesRegex(ValueError, "model"):
            ask_ollama("contract A {}", [], "../../other")

    def test_cloud_model_is_rejected_for_privacy(self):
        with self.assertRaisesRegex(ValueError, "cloud"):
            ask_ollama("contract A {}", [], "gemma4:cloud")

    def test_ollama_failure_is_bounded(self):
        with patch("integrations.HTTPConnection", side_effect=OSError("private payload")):
            with self.assertRaisesRegex(RuntimeError, "Ollama") as error:
                ask_ollama("contract A {}", [], "local-model")
        self.assertNotIn("private payload", str(error.exception))


if __name__ == "__main__":
    unittest.main()
