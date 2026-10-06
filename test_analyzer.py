import json
import subprocess
import sys
import time
import urllib.request
import unittest

from analyzer import analyze_password


class AnalyzerTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        result = analyze_password("password")
        self.assertEqual(result.score, 0)
        self.assertIn("commonly used", result.warnings[0])

    def test_stronger_password_receives_higher_score(self):
        weak = analyze_password("abc123")
        strong = analyze_password("Purple!River7$Comet#92")
        self.assertGreater(strong.score, weak.score)
        self.assertGreater(strong.entropy_bits, weak.entropy_bits)

    def test_empty_password_is_safe_to_analyze(self):
        result = analyze_password("")
        self.assertEqual(result.length, 0)
        self.assertEqual(result.score, 0)

    def test_api_returns_json(self):
        process = subprocess.Popen([sys.executable, "server.py"], stdout=subprocess.DEVNULL)
        try:
            time.sleep(0.2)
            request = urllib.request.Request(
                "http://127.0.0.1:8000/api/analyze",
                data=json.dumps({"password": "abc123"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                body = json.loads(response.read())
            self.assertIn("score", body)
            self.assertNotIn("password", body)
        finally:
            process.terminate()
            process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()