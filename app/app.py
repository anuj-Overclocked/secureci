from flask import Flask, render_template, redirect, url_for

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIRECTORY = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

REPORT_DIRECTORY = os.path.join(
    BASE_DIRECTORY,
    "reports"
)

REPORT_FILE = os.path.join(
    REPORT_DIRECTORY,
    "vulnerability-report.json"
)

PREVIOUS_REPORT_FILE = os.path.join(
    REPORT_DIRECTORY,
    "previous-report.json"
)

SCANNER_FILE = os.path.join(
    BASE_DIRECTORY,
    "github_scanner.py"
)

LOCAL_SCANNER_FILE = os.path.join(
    BASE_DIRECTORY,
    "local_scanner.py"
)

RESCAN_TIMEOUT = 900

RESCAN_IN_PROGRESS = False


def get_python_executable():
    """Return the Python executable from the project venv if available, else sys.executable."""
    candidates = [
        os.path.join(BASE_DIRECTORY, "venv", "Scripts", "python.exe"),
        os.path.join(BASE_DIRECTORY, "venv", "bin", "python"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return sys.executable


# ============================================================
# DEFAULT REPORT
# ============================================================

def default_report():
    return {
        "project": "SecureCI",
        "repository": "No repository scanned",
        "scan_status": "NOT SCANNED",
        "total_vulnerabilities": 0,
        "severity_summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        "security_gate": "NOT SCANNED",
        "scanner_status": {
            "status": "NOT SCANNED",
            "errors": []
        },
        "repository_summary": {
            "files_scanned": 0,
            "folders_scanned": 0,
            "vulnerable_files": 0
        },
        "file_summary": [],
        "findings": [],
        "scan_time": "Not available"
    }


# ============================================================
# LOAD REPORT
# ============================================================

def load_report():
    if not os.path.exists(REPORT_FILE):
        return default_report()

    try:
        with open(
            REPORT_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            report = json.load(file)

        report.setdefault("project", "SecureCI")
        report.setdefault("repository", "Unknown")
        report.setdefault("scan_status", "COMPLETED")
        report.setdefault("scanner_status", {"status": "COMPLETED", "errors": []})
        report.setdefault("severity_summary", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        report.setdefault("findings", [])
        report.setdefault("security_gate", "PASS")
        report.setdefault("repository_summary", {"files_scanned": 0, "folders_scanned": 0, "vulnerable_files": 0})
        report.setdefault("file_summary", [])
        report.setdefault("scan_time", "Not available")

        report["total_vulnerabilities"] = len(report["findings"])

        severity_summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in report["findings"]:
            severity = str(finding.get("severity", "MEDIUM")).upper()
            if severity in severity_summary:
                severity_summary[severity] += 1

        report["severity_summary"] = severity_summary

        scanner_status = report.get("scanner_status", {})
        scanner_errors = scanner_status.get("errors", [])

        if (
            report.get("scan_status") == "FAILED"
            or scanner_errors
            or report.get("security_gate") == "SCAN ERROR"
        ):
            report["security_gate"] = "SCAN ERROR"
            report["scan_status"] = "FAILED"
        elif report["findings"] or report.get("security_gate") == "BLOCKED":
            report["security_gate"] = "BLOCKED"
        else:
            report["security_gate"] = "PASS"

        for finding in report["findings"]:
            finding.setdefault("scanner", "Security Scanner")
            finding.setdefault("severity", "MEDIUM")
            finding.setdefault("type", "Security Vulnerability")
            finding.setdefault("rule", "Security Rule")
            finding.setdefault("file", "Unknown")
            finding.setdefault("line", "Unknown")
            finding.setdefault("message", "A security issue was detected.")
            finding.setdefault("recommended_fix", "Review and fix the reported issue.")

        if report["scan_time"] == "Not available":
            modified_time = os.path.getmtime(REPORT_FILE)
            report["scan_time"] = datetime.fromtimestamp(
                modified_time
            ).strftime("%d %b %Y, %I:%M %p")

        return report

    except Exception as error:
        print("Error reading report:")
        print(error)
        return default_report()


# ============================================================
# SAVE PREVIOUS REPORT
# ============================================================

def save_previous_report():
    if not os.path.exists(REPORT_FILE):
        return

    try:
        os.makedirs(REPORT_DIRECTORY, exist_ok=True)
        shutil.copy2(REPORT_FILE, PREVIOUS_REPORT_FILE)
        print("Previous security report saved.")
    except Exception as error:
        print("Could not save previous report:")
        print(error)


# ============================================================
# RUN RESCAN
# ============================================================

def save_scan_error_report(repository, message):
    error_report = {
        "project": "SecureCI",
        "repository": repository,
        "scan_status": "FAILED",
        "security_gate": "SCAN ERROR",
        "total_vulnerabilities": 0,
        "severity_summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        "scanner_status": {
            "status": "FAILED",
            "errors": [
                {
                    "scanner": "SecureCI",
                    "message": message
                }
            ]
        },
        "repository_summary": {
            "files_scanned": 0,
            "folders_scanned": 0,
            "vulnerable_files": 0
        },
        "file_summary": [],
        "findings": [],
        "scan_time": datetime.now().strftime("%d %b %Y, %I:%M %p")
    }

    os.makedirs(REPORT_DIRECTORY, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(error_report, file, indent=4)


def run_rescan():
    global RESCAN_IN_PROGRESS

    if RESCAN_IN_PROGRESS:
        print("A rescan is already running.")
        return False

    report = load_report()
    repository = str(report.get("repository", "")).strip()

    if (
        not repository
        or repository == "No repository scanned"
        or repository == "Unknown"
    ):
        print("No repository is available for rescan.")
        return False

    save_previous_report()
    RESCAN_IN_PROGRESS = True

    print()
    print("=" * 60)
    print("SECURECI RESCAN STARTED")
    print("=" * 60)
    print()
    print("Repository:", repository)
    print()

    py_exe = get_python_executable()

    try:
        if os.path.isdir(repository):
            if not os.path.exists(LOCAL_SCANNER_FILE):
                print("local_scanner.py was not found.")
                save_scan_error_report(repository, "local_scanner.py was not found.")
                return False

            command = [
                py_exe,
                LOCAL_SCANNER_FILE,
                "--path",
                repository,
                "--no-dashboard"
            ]
        else:
            if not os.path.exists(SCANNER_FILE):
                print("github_scanner.py was not found.")
                save_scan_error_report(repository, "github_scanner.py was not found.")
                return False

            command = [
                py_exe,
                SCANNER_FILE,
                "--repo-url",
                repository,
                "--no-dashboard"
            ]

        result = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            cwd=BASE_DIRECTORY,
            timeout=RESCAN_TIMEOUT
        )

        print()
        print("Scanner output:")
        print(result.stdout)

        if result.stderr:
            print()
            print("Scanner messages:")
            print(result.stderr)

        if not os.path.exists(REPORT_FILE):
            print()
            print("RESCAN FAILED.")
            print("The scanner did not generate a report.")
            save_scan_error_report(
                repository,
                "The scanner did not generate a report."
            )
            return False

        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as file:
                new_report = json.load(file)
        except Exception as error:
            print()
            print("RESCAN FAILED.")
            print("The new report could not be read.")
            print(error)
            save_scan_error_report(
                repository,
                f"The new report could not be read: {error}"
            )
            return False

        new_report["scan_time"] = datetime.now().strftime("%d %b %Y, %I:%M %p")

        with open(REPORT_FILE, "w", encoding="utf-8") as file:
            json.dump(new_report, file, indent=4)

        if result.returncode != 0:
            print()
            print("RESCAN FINISHED WITH SCANNER ERROR.")
            print(f"Scanner exit code: {result.returncode}")
            return False

        print()
        print("RESCAN COMPLETED.")
        print(f"Security Gate: {new_report.get('security_gate', 'UNKNOWN')}")
        return True

    except subprocess.TimeoutExpired:
        print()
        print("RESCAN TIMED OUT.")
        print(f"Timeout: {RESCAN_TIMEOUT} seconds.")
        return False

    except Exception as error:
        print()
        print("RESCAN ERROR")
        print(error)
        save_scan_error_report(
            repository,
            f"Rescan error: {error}"
        )
        return False

    finally:
        RESCAN_IN_PROGRESS = False


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    report = load_report()
    previous_report = None

    if os.path.exists(PREVIOUS_REPORT_FILE):
        try:
            with open(PREVIOUS_REPORT_FILE, "r", encoding="utf-8") as file:
                previous_report = json.load(file)
        except Exception:
            previous_report = None

    return render_template(
        "dashboard.html",
        report=report,
        previous_report=previous_report
    )


# ============================================================
# RESCAN ROUTE
# ============================================================

@app.route(
    "/rescan",
    methods=["POST"]
)
def rescan():
    success = run_rescan()
    return redirect(
        url_for(
            "home",
            rescan="completed" if success else "failed"
        )
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
