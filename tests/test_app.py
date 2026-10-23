import os
import json
import tempfile
import unittest
from pathlib import Path

from app.app import app, default_report, load_report
import github_scanner
import security_gate


def test_basic():
    assert 1 + 1 == 2


class TestSecureCI(unittest.TestCase):

    def test_basic(self):
        self.assertEqual(1 + 1, 2)

    def test_default_report_structure(self):
        rep = default_report()
        self.assertEqual(rep["project"], "SecureCI")
        self.assertEqual(rep["security_gate"], "NOT SCANNED")
        self.assertEqual(rep["total_vulnerabilities"], 0)
        self.assertEqual(rep["scan_status"], "NOT SCANNED")

    def test_load_report_pass(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_report_file = Path(tmp_dir) / "vulnerability-report.json"
            dummy_data = {
                "project": "SecureCI",
                "repository": "test-repo",
                "scan_status": "COMPLETED",
                "security_gate": "PASS",
                "scanner_status": {"status": "COMPLETED", "errors": []},
                "findings": [],
                "total_vulnerabilities": 0
            }
            test_report_file.write_text(json.dumps(dummy_data), encoding="utf-8")

            old_report_file = getattr(load_report, "__globals__", {}).get("REPORT_FILE")
            from app import app as app_module
            original = app_module.REPORT_FILE
            try:
                app_module.REPORT_FILE = str(test_report_file)
                report = load_report()
                self.assertEqual(report["security_gate"], "PASS")
                self.assertEqual(report["scan_status"], "COMPLETED")
                self.assertEqual(report["total_vulnerabilities"], 0)
            finally:
                app_module.REPORT_FILE = original

    def test_load_report_blocked(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_report_file = Path(tmp_dir) / "vulnerability-report.json"
            dummy_data = {
                "project": "SecureCI",
                "repository": "test-repo",
                "scan_status": "COMPLETED",
                "security_gate": "BLOCKED",
                "scanner_status": {"status": "COMPLETED", "errors": []},
                "findings": [
                    {
                        "scanner": "Gitleaks",
                        "severity": "HIGH",
                        "type": "Secret Exposure",
                        "rule": "test-rule",
                        "file": "config.py",
                        "line": 1,
                        "message": "Secret leak",
                        "recommended_fix": "Remove secret"
                    }
                ]
            }
            test_report_file.write_text(json.dumps(dummy_data), encoding="utf-8")

            from app import app as app_module
            original = app_module.REPORT_FILE
            try:
                app_module.REPORT_FILE = str(test_report_file)
                report = load_report()
                self.assertEqual(report["security_gate"], "BLOCKED")
                self.assertEqual(report["total_vulnerabilities"], 1)
                self.assertEqual(report["severity_summary"]["HIGH"], 1)
            finally:
                app_module.REPORT_FILE = original

    def test_load_report_scan_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_report_file = Path(tmp_dir) / "vulnerability-report.json"
            dummy_data = {
                "project": "SecureCI",
                "repository": "test-repo",
                "scan_status": "FAILED",
                "security_gate": "SCAN ERROR",
                "scanner_status": {
                    "status": "FAILED",
                    "errors": [{"scanner": "Semgrep", "message": "Failed"}]
                },
                "findings": []
            }
            test_report_file.write_text(json.dumps(dummy_data), encoding="utf-8")

            from app import app as app_module
            original = app_module.REPORT_FILE
            try:
                app_module.REPORT_FILE = str(test_report_file)
                report = load_report()
                self.assertEqual(report["security_gate"], "SCAN ERROR")
                self.assertEqual(report["scan_status"], "FAILED")
            finally:
                app_module.REPORT_FILE = original

    def test_discover_files_ignores_venv_and_hidden(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
            (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")

            venv_dir = tmp_path / "venv" / "sub"
            venv_dir.mkdir(parents=True)
            (venv_dir / "bad.py").write_text("bad", encoding="utf-8")

            git_dir = tmp_path / ".git"
            git_dir.mkdir()
            (git_dir / "config").write_text("git config", encoding="utf-8")

            files = github_scanner.discover_files(tmp_path)
            self.assertIn("app.py", files)
            self.assertIn("README.md", files)
            self.assertFalse(any("venv" in f for f in files))
            self.assertFalse(any(".git" in f for f in files))

    def test_tools_found(self):
        self.assertIsNotNone(github_scanner.find_tool_executable("gitleaks"))
        self.assertIsNotNone(github_scanner.find_tool_executable("semgrep"))
        self.assertIsNotNone(github_scanner.find_tool_executable("pip-audit"))


if __name__ == "__main__":
    unittest.main()
