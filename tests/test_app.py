import os
import json
import tempfile
import unittest
from pathlib import Path

from app.app import app, default_report, load_report
import github_scanner
import local_scanner
import security_gate


def test_basic():
    assert 1 + 1 == 2


class TestSecureCI(unittest.TestCase):

    def setUp(self):
        github_scanner.reset_scan_state()

    def test_01_valid_local_project_path(self):
        """Case 1: Valid local project path scans successfully."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "main.py").write_text("def hello(): return 'world'\n", encoding="utf-8")
            (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")

            report = local_scanner.scan_local_directory(tmp_path)
            self.assertIsNotNone(report)
            self.assertEqual(report["scan_status"], "COMPLETED")
            self.assertIn("security_gate", report)

    def test_02_invalid_and_nonexistent_project_path(self):
        """Case 2: Invalid, non-existent, or non-directory paths return error."""
        # Non-existent folder
        report_none = local_scanner.scan_local_directory("Z:\\NonExistentPath_XYZ_12345")
        self.assertIsNone(report_none)

        # Blank input
        report_blank = local_scanner.scan_local_directory("   ")
        self.assertIsNone(report_blank)

        # File instead of directory
        with tempfile.NamedTemporaryFile() as tmp_file:
            report_file = local_scanner.scan_local_directory(tmp_file.name)
            self.assertIsNone(report_file)

    def test_03_project_containing_controlled_fake_secret(self):
        """Case 3: Project with controlled fake credential triggers Gitleaks and blocks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "creds.py").write_text(
                'TOKEN = "SECURECI_DEMO_SECRET_XYZ998877"\n',
                encoding="utf-8"
            )
            gitleaks_findings = github_scanner.scan_with_gitleaks(tmp_path)
            self.assertGreaterEqual(len(gitleaks_findings), 1)
            self.assertEqual(gitleaks_findings[0]["scanner"], "Gitleaks")
            self.assertEqual(gitleaks_findings[0]["severity"], "HIGH")

            report = github_scanner.build_final_report(
                str(tmp_path),
                tmp_path,
                gitleaks_findings,
                ["creds.py"],
                0
            )
            self.assertEqual(report["security_gate"], "BLOCKED")

    def test_04_project_containing_insecure_code_pattern(self):
        """Case 4: Project with SQL injection pattern triggers Semgrep and blocks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text(
                'query = "SELECT * FROM users WHERE username = \'" + user_input + "\'"\n',
                encoding="utf-8"
            )
            semgrep_findings = github_scanner.scan_with_semgrep(tmp_path)
            self.assertGreaterEqual(len(semgrep_findings), 1)
            self.assertEqual(semgrep_findings[0]["scanner"], "Semgrep")

            report = github_scanner.build_final_report(
                str(tmp_path),
                tmp_path,
                semgrep_findings,
                ["app.py"],
                0
            )
            self.assertEqual(report["security_gate"], "BLOCKED")

    def test_05_project_with_outdated_vulnerable_dependency(self):
        """Case 5: Project with vulnerable dependency triggers pip-audit and blocks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "requirements.txt").write_text(
                "requests==2.19.1\n",
                encoding="utf-8"
            )
            pip_findings = github_scanner.scan_with_pip_audit(tmp_path)
            self.assertGreaterEqual(len(pip_findings), 1)
            self.assertEqual(pip_findings[0]["scanner"], "pip-audit")

            report = github_scanner.build_final_report(
                str(tmp_path),
                tmp_path,
                pip_findings,
                ["requirements.txt"],
                0
            )
            self.assertEqual(report["security_gate"], "BLOCKED")

    def test_06_clean_project_no_findings(self):
        """Case 6: Clean project with no vulnerabilities produces PASS."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text(
                "def add(a, b):\n    return a + b\n",
                encoding="utf-8"
            )
            (tmp_path / "requirements.txt").write_text("\n", encoding="utf-8")

            report = local_scanner.scan_local_directory(tmp_path)
            self.assertIsNotNone(report)
            self.assertEqual(report["total_vulnerabilities"], 0)
            self.assertEqual(report["security_gate"], "PASS")

    def test_07_missing_scanner_executable(self):
        """Case 7: Missing scanner tool records scan error and shows SCAN ERROR."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text("print('test')\n", encoding="utf-8")

            original_finder = github_scanner.find_tool_executable
            try:
                # Simulate Gitleaks not being installed
                def mock_finder(name):
                    if name == "gitleaks":
                        return None
                    return original_finder(name)

                github_scanner.find_tool_executable = mock_finder
                github_scanner.reset_scan_state()

                github_scanner.scan_with_gitleaks(tmp_path)
                self.assertGreaterEqual(len(github_scanner.SCAN_ERRORS), 1)
                self.assertEqual(github_scanner.SCAN_ERRORS[0]["scanner"], "Gitleaks")

                report = github_scanner.build_final_report(
                    str(tmp_path), tmp_path, [], ["app.py"], 0
                )
                self.assertEqual(report["security_gate"], "SCAN ERROR")
                self.assertEqual(report["scan_status"], "FAILED")
            finally:
                github_scanner.find_tool_executable = original_finder
                github_scanner.reset_scan_state()

    def test_08_scanner_process_failure(self):
        """Case 8: Subprocess crash records scan error and yields SCAN ERROR."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text("print('test')\n", encoding="utf-8")

            original_run_command = github_scanner.run_command
            try:
                # Simulate crash/timeout
                github_scanner.run_command = lambda *args, **kwargs: (-1, "", "Process crash simulated")
                github_scanner.reset_scan_state()

                github_scanner.scan_with_gitleaks(tmp_path)
                self.assertGreaterEqual(len(github_scanner.SCAN_ERRORS), 1)

                report = github_scanner.build_final_report(
                    str(tmp_path), tmp_path, [], ["app.py"], 0
                )
                self.assertEqual(report["security_gate"], "SCAN ERROR")
                self.assertEqual(report["scan_status"], "FAILED")
            finally:
                github_scanner.run_command = original_run_command
                github_scanner.reset_scan_state()

    def test_09_report_generation_and_dashboard_report_loading(self):
        """Case 9: Report is saved with all required metadata and loaded accurately."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_report_file = Path(tmp_dir) / "vulnerability-report.json"
            dummy_data = {
                "project": "SecureCI",
                "repository": "D:\\Projects\\TestApp",
                "scan_time": "24 Oct 2026, 04:00 AM",
                "scan_status": "COMPLETED",
                "security_gate": "PASS",
                "scanner_status": {"status": "COMPLETED", "errors": []},
                "findings": [],
                "total_vulnerabilities": 0,
                "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "repository_summary": {"files_scanned": 1, "folders_scanned": 0, "vulnerable_files": 0},
                "file_summary": [{"file": "main.py", "status": "PASS", "severity": "NONE", "issues": 0}]
            }
            test_report_file.write_text(json.dumps(dummy_data), encoding="utf-8")

            from app import app as app_module
            original = app_module.REPORT_FILE
            try:
                app_module.REPORT_FILE = str(test_report_file)
                loaded = load_report()
                self.assertEqual(loaded["repository"], "D:\\Projects\\TestApp")
                self.assertEqual(loaded["security_gate"], "PASS")
                self.assertEqual(loaded["total_vulnerabilities"], 0)
                self.assertEqual(loaded["scan_time"], "24 Oct 2026, 04:00 AM")
            finally:
                app_module.REPORT_FILE = original

    def test_10_second_scan_after_manual_fix(self):
        """Case 10: Two-scan workflow: initial scan BLOCKED -> fix code -> second scan PASS."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            target_file = tmp_path / "config.py"

            # 1. First state: contains a secret
            target_file.write_text(
                'SECRET_KEY = "SECURECI_DEMO_SECRET_REVOKEME123"\n',
                encoding="utf-8"
            )
            first_report = local_scanner.scan_local_directory(tmp_path)
            self.assertEqual(first_report["security_gate"], "BLOCKED")
            self.assertGreaterEqual(first_report["total_vulnerabilities"], 1)

            # 2. Developer manually remediates the issue
            target_file.write_text(
                '# Secret removed. Using environment variable.\nimport os\nSECRET_KEY = os.getenv("SECRET_KEY", "default")\n',
                encoding="utf-8"
            )

            # 3. Fresh second scan against the exact same folder
            second_report = local_scanner.scan_local_directory(tmp_path)
            self.assertEqual(second_report["security_gate"], "PASS")
            self.assertEqual(second_report["total_vulnerabilities"], 0)

    def test_11_tools_resolved_in_environment(self):
        """Case 11: Security engines (Gitleaks, Semgrep, pip-audit) resolve in environment."""
        self.assertIsNotNone(github_scanner.find_tool_executable("gitleaks"))
        self.assertIsNotNone(github_scanner.find_tool_executable("semgrep"))
        self.assertIsNotNone(github_scanner.find_tool_executable("pip-audit"))


if __name__ == "__main__":
    unittest.main()
