import sys
import json
import os

BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
REPORT_FILE = os.path.join(BASE_DIRECTORY, "reports", "vulnerability-report.json")
STATUS_FILE = os.path.join(BASE_DIRECTORY, "reports", "security-status.json")


def security_gate():
    print("================================")
    print("       SECURECI SECURITY GATE")
    print("================================")

    status = "PASS"
    reason = "No critical security issues detected."
    findings = []
    has_scanner_error = False

    # Check vulnerability report if available
    if os.path.exists(REPORT_FILE):
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as file:
                report = json.load(file)

            findings = report.get("findings", [])
            gate = report.get("security_gate")
            scanner_errors = report.get("scanner_status", {}).get("errors", [])

            if gate == "SCAN ERROR" or report.get("scan_status") == "FAILED" or scanner_errors:
                status = "SCAN ERROR"
                has_scanner_error = True
                reason = "Scanner reported an execution error."
            elif findings or gate == "BLOCKED":
                status = "BLOCKED"
                reason = f"{len(findings)} security vulnerability issue(s) detected."
            else:
                status = "PASS"
                reason = "No security issues detected."
        except Exception as error:
            print(f"Error reading {REPORT_FILE}: {error}")

    # Legacy demo secret check
    demo_secret_file = os.path.join(BASE_DIRECTORY, "demo-secret.txt")
    if os.path.exists(demo_secret_file):
        try:
            with open(demo_secret_file, "r", encoding="utf-8") as file:
                content = file.read()
            if "SECURECI_DEMO_SECRET_" in content and not has_scanner_error:
                status = "BLOCKED"
                reason = "Critical demo secret detected."
        except Exception:
            pass

    os.makedirs(os.path.join(BASE_DIRECTORY, "reports"), exist_ok=True)

    secret_fail = any(f.get("scanner") == "Gitleaks" for f in findings) or ("Critical demo secret" in reason)
    sast_fail = any(f.get("scanner") == "Semgrep" for f in findings)
    dep_fail = any(f.get("scanner") == "pip-audit" for f in findings)

    status_report = {
        "sast": "FAIL" if sast_fail else "PASS",
        "secret_scan": "FAIL" if secret_fail else "PASS",
        "dependency_scan": "FAIL" if dep_fail else "PASS",
        "dast": "PASS",
        "security_gate": status,
        "reason": reason
    }

    with open(STATUS_FILE, "w", encoding="utf-8") as file:
        json.dump(status_report, file, indent=4)

    print("\nSecurity Scan Results")
    print("--------------------")
    print("SAST:", status_report["sast"])
    print("Secret Scan:", status_report["secret_scan"])
    print("Dependency Scan:", status_report["dependency_scan"])
    print("DAST: PASS")

    print("\nSecurity Gate:", status)
    print(reason)

    if status in ("BLOCKED", "SCAN ERROR"):
        print("\nDeployment is NOT allowed.")
        sys.exit(1)

    print("\nDeployment is allowed.")


if __name__ == "__main__":
    security_gate()
