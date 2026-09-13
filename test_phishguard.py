"""اختبارات PhishGuard باستخدام unittest من المكتبة القياسية."""

import json
import tempfile
import unittest
from pathlib import Path

from phishguard.config import ConfigurationError, load_config
from phishguard.scanner import scan_csv_file, scan_file, scan_text, scan_url, summarize


class PhishGuardTests(unittest.TestCase):
    def test_safe_https_url(self):
        result = scan_url("https://example.com/about")
        self.assertEqual(result.verdict, "SAFE")
        self.assertEqual(result.risk_score, 0)
        self.assertFalse(result.metadata["network_access"])

    def test_high_risk_ip_and_http_url(self):
        result = scan_url("http://192.168.1.10/login?password=demo")
        self.assertIn(result.verdict, {"HIGH_RISK", "CRITICAL"})
        self.assertGreaterEqual(result.risk_score, 55)
        codes = {item.code for item in result.findings}
        self.assertTrue({"URL002", "URL003"}.issubset(codes))

    def test_text_with_urgency_and_credentials(self):
        result = scan_text("URGENT: verify your account password immediately at https://bit.ly/a")
        self.assertGreaterEqual(result.risk_score, 25)
        self.assertGreaterEqual(result.metadata["url_count"], 1)
        self.assertGreaterEqual(len(result.findings), 2)

    def test_file_hash_and_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_text("Your account is suspended. Verify at https://example.com/login", encoding="utf-8")
            result = scan_file(str(path))
            self.assertEqual(result.target_type, "file")
            self.assertEqual(len(result.metadata["sha256"]), 64)
            self.assertEqual(result.metadata["file_extension"], ".eml")

    def test_csv_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.csv"
            path.write_text("url\nhttps://example.com\nhttp://10.0.0.2/login\n", encoding="utf-8")
            results = scan_csv_file(str(path))
            self.assertEqual(len(results), 2)
            self.assertEqual(summarize(results)["total"], 2)

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            scan_url("not-a-url")

    def test_bad_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps({"output_format": "xml"}), encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                load_config(str(path))


if __name__ == "__main__":
    unittest.main()
