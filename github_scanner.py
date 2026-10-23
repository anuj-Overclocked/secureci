import argparse
from datetime import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# SECURECI CONFIGURATION
# ============================================================

BASE_DIRECTORY = Path(__file__).resolve().parent

REPORT_DIRECTORY = BASE_DIRECTORY / "reports"

FINAL_REPORT = REPORT_DIRECTORY / "vulnerability-report.json"

GITLEAKS_REPORT = REPORT_DIRECTORY / "gitleaks-report.json"

SEMGREP_REPORT = REPORT_DIRECTORY / "semgrep-report.json"

PIP_AUDIT_REPORT = REPORT_DIRECTORY / "pip-audit-report.json"

GITLEAKS_CONFIG = BASE_DIRECTORY / ".gitleaks.toml"

# Errors from security tools are tracked separately so SecureCI
# never reports PASS when a scanner actually failed.
SCAN_ERRORS = []


# Directories that should not be treated as application source.
IGNORED_DIRECTORIES = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".secureci",
    "reports",
    "scans",
}


# File extensions that are normally not useful for
# source-code security analysis.
IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".zip",
    ".rar",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def print_header(title):
    print()
    print("=" * 65)
    print(title)
    print("=" * 65)


def print_step(number, title):
    print()
    print("-" * 65)
    print(f"STEP {number} - {title}")
    print("-" * 65)


def ensure_report_directory():
    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )


def reset_scan_state():
    SCAN_ERRORS.clear()


def record_scan_error(scanner_name, message):
    SCAN_ERRORS.append({
        "scanner": scanner_name,
        "message": message
    })


def remove_old_scanner_report(file_path):
    try:
        if file_path.exists():
            file_path.unlink()
    except Exception as error:
        record_scan_error(
            "SecureCI",
            f"Could not remove old scanner report {file_path.name}: {error}"
        )


def find_tool_executable(tool_name):
    """Find a security scanner executable in PATH, python Scripts/bin, or project venv."""
    # 1. System PATH
    found = shutil.which(tool_name)
    if found:
        return found

    exe_name = tool_name + (".exe" if os.name == "nt" else "")

    # 2. Python environment directory
    py_dir = Path(sys.executable).parent
    candidate = py_dir / exe_name
    if candidate.is_file():
        return str(candidate)

    # 3. Base directory venv / Scripts or bin
    for sub in ("Scripts", "bin"):
        venv_candidate = BASE_DIRECTORY / "venv" / sub / exe_name
        if venv_candidate.is_file():
            return str(venv_candidate)
        root_candidate = BASE_DIRECTORY / sub / exe_name
        if root_candidate.is_file():
            return str(root_candidate)

    return None


def get_python_executable():
    """Return the Python executable from the project venv if available, else sys.executable."""
    candidates = [
        BASE_DIRECTORY / "venv" / "Scripts" / "python.exe",
        BASE_DIRECTORY / "venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def is_dashboard_running(host="127.0.0.1", port=5000):
    """Check if the SecureCI dashboard is already listening on the configured port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def run_command(
    command,
    cwd=None,
    timeout=300
):
    try:
        env = os.environ.copy()
        extra_paths = [
            str(Path(sys.executable).parent),
            str(BASE_DIRECTORY / "venv" / ("Scripts" if os.name == "nt" else "bin")),
            str(BASE_DIRECTORY / ("Scripts" if os.name == "nt" else "bin")),
        ]
        current_path = env.get("PATH", "")
        valid_extras = [p for p in extra_paths if os.path.exists(p)]
        if valid_extras:
            env["PATH"] = os.pathsep.join(valid_extras) + os.pathsep + current_path

        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            env=env
        )

        return result.returncode, result.stdout, result.stderr

    except FileNotFoundError:
        return -1, "", f"Command not found: {command[0]}"

    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out."

    except Exception as error:
        return -3, "", str(error)


def load_json_file(file_path):
    if not file_path.exists():
        return None

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except Exception:
        return None


def save_json_file(
    file_path,
    data
):
    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            data,
            file,
            indent=4
        )


# ============================================================
# GITHUB URL VALIDATION
# ============================================================

def validate_github_url(repo_url):
    repo_url = repo_url.strip()
    parsed = urlparse(repo_url)

    if parsed.scheme not in {"http", "https"}:
        return False

    if parsed.netloc.lower() != "github.com":
        return False

    path = parsed.path.strip("/")
    parts = path.split("/")

    if len(parts) < 2:
        return False

    return True


# ============================================================
# CLONE REPOSITORY
# ============================================================

def clone_repository(
    repo_url,
    destination
):
    print("Cloning repository...")

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        repo_url,
        str(destination)
    ]

    code, stdout, stderr = run_command(
        command,
        timeout=180
    )

    if code != 0:
        print()
        print("Git clone failed.")
        if stderr:
            print(stderr)
        return False

    print("Repository cloned successfully.")
    return True


# ============================================================
# FILE DISCOVERY
# ============================================================

def discover_files(
    repository_directory
):
    files = []

    for root, directories, filenames in os.walk(
        repository_directory
    ):
        # Remove ignored directories from traversal.
        directories[:] = [
            directory
            for directory in directories
            if directory not in IGNORED_DIRECTORIES
        ]

        for filename in filenames:
            file_path = Path(root) / filename

            try:
                relative_path = file_path.relative_to(
                    repository_directory
                )
            except ValueError:
                continue

            if file_path.suffix.lower() in IGNORED_EXTENSIONS:
                continue

            files.append(
                str(relative_path).replace(
                    "\\",
                    "/"
                )
            )

    return sorted(files)


def normalize_repository_path(
    repository_directory,
    file_path
):
    """Return a clean repository-relative path for dashboard reports."""
    if not file_path:
        return "Unknown"

    try:
        path = Path(str(file_path))

        if path.is_absolute():
            try:
                path = path.relative_to(repository_directory)
            except ValueError:
                pass

        return str(path).replace("\\", "/")

    except Exception:
        return str(file_path).replace("\\", "/")


def count_directories(
    repository_directory
):
    count = 0

    for root, directories, filenames in os.walk(
        repository_directory
    ):
        directories[:] = [
            directory
            for directory in directories
            if directory not in IGNORED_DIRECTORIES
        ]

        count += len(directories)

    return count


# ============================================================
# FINDING CREATION
# ============================================================

def create_finding(
    scanner,
    severity,
    finding_type,
    rule,
    file_path,
    line,
    message,
    recommended_fix
):
    return {
        "scanner": scanner,
        "severity": severity.upper(),
        "type": finding_type,
        "rule": rule,
        "file": file_path,
        "line": line,
        "message": message,
        "recommended_fix": recommended_fix
    }


# ============================================================
# GITLEAKS
# ============================================================

def scan_with_gitleaks(
    repository_directory
):
    print_step(
        2,
        "SECRET SCAN - GITLEAKS"
    )

    findings = []

    gitleaks_exe = find_tool_executable("gitleaks")

    if not gitleaks_exe:
        message = "Gitleaks is not installed."
        print(message)
        record_scan_error(
            "Gitleaks",
            message
        )
        return findings

    # Gitleaks v8 uses the target directory as a positional
    # argument for the "dir" command.
    command = [
        gitleaks_exe,
        "dir",
        str(repository_directory),
        "--report-format",
        "json",
        "--report-path",
        str(GITLEAKS_REPORT),
        "--redact",
        "--exit-code",
        "1"
    ]

    if GITLEAKS_CONFIG.exists():
        command.extend([
            "--config",
            str(GITLEAKS_CONFIG)
        ])

    remove_old_scanner_report(GITLEAKS_REPORT)

    code, stdout, stderr = run_command(
        command,
        timeout=300
    )

    # Code 0 = no leak.
    # Code 1 = leak detected.
    # Anything else = scanner failure.
    if code == 0:
        print("Gitleaks: PASS")
        raw_results = load_json_file(GITLEAKS_REPORT)
        if raw_results is None:
            raw_results = []

    elif code == 1:
        print("Gitleaks: FINDINGS DETECTED")
        raw_results = load_json_file(GITLEAKS_REPORT)
        if raw_results is None:
            message = "Gitleaks did not produce a valid JSON report."
            print(message)
            record_scan_error(
                "Gitleaks",
                message
            )
            return findings

    else:
        message = (
            stderr.strip()
            or stdout.strip()
            or "Gitleaks returned an unexpected exit code."
        )
        print("Gitleaks scanner error.")
        print(message)
        record_scan_error(
            "Gitleaks",
            message
        )
        return findings

    if not isinstance(raw_results, list):
        return findings

    for result in raw_results:
        raw_file = result.get(
            "File",
            "Unknown"
        )

        # Convert absolute cloned path into repository-relative path.
        try:
            relative_file = str(
                Path(raw_file).relative_to(
                    repository_directory
                )
            ).replace(
                "\\",
                "/"
            )
        except ValueError:
            relative_file = raw_file

        description = result.get(
            "Description",
            "Potential secret detected."
        )

        rule_id = result.get(
            "RuleID",
            "gitleaks-secret"
        )

        line = result.get(
            "StartLine",
            "Unknown"
        )

        finding = create_finding(
            scanner="Gitleaks",
            severity="HIGH",
            finding_type="Secret Exposure",
            rule=rule_id,
            file_path=relative_file,
            line=line,
            message=description,
            recommended_fix=(
                "Remove the secret from source code. "
                "Use environment variables or a secure "
                "secret manager instead. If this was a "
                "real credential, rotate or revoke it."
            )
        )

        findings.append(finding)

    return findings


# ============================================================
# SEMGREP
# ============================================================

def scan_with_semgrep(
    repository_directory
):
    print_step(
        3,
        "SOURCE CODE SCAN - SEMGREP"
    )

    findings = []

    semgrep_exe = find_tool_executable("semgrep")

    if not semgrep_exe:
        message = "Semgrep is not installed."
        print(message)
        record_scan_error(
            "Semgrep",
            message
        )
        return findings

    remove_old_scanner_report(SEMGREP_REPORT)

    command = [
        semgrep_exe,
        "scan",
        "--config",
        "auto",
        "--json",
        "--quiet",
        "--metrics=off",
        str(repository_directory)
    ]

    local_rules = BASE_DIRECTORY / "semgrep-rules.yml"
    if local_rules.exists():
        command.extend([
            "--config",
            str(local_rules)
        ])

    code, stdout, stderr = run_command(
        command,
        timeout=600
    )

    # If --config auto failed (e.g. offline or registry unavailable), retry with local rules
    if code not in (0, 1) and local_rules.exists():
        fallback_command = [
            semgrep_exe,
            "scan",
            "--config",
            str(local_rules),
            "--json",
            "--quiet",
            "--metrics=off",
            str(repository_directory)
        ]
        fb_code, fb_stdout, fb_stderr = run_command(
            fallback_command,
            timeout=300
        )
        if fb_code in (0, 1):
            code, stdout, stderr = fb_code, fb_stdout, fb_stderr

    # Semgrep's JSON output is captured directly from stdout.
    raw_report = None
    stdout_text = (stdout or "").strip()

    if stdout_text:
        try:
            raw_report = json.loads(stdout_text)
        except json.JSONDecodeError:
            first_brace = stdout_text.find("{")
            last_brace = stdout_text.rfind("}")
            if first_brace != -1 and last_brace > first_brace:
                candidate = stdout_text[first_brace:last_brace + 1]
                try:
                    raw_report = json.loads(candidate)
                except json.JSONDecodeError:
                    raw_report = None

    if raw_report is not None:
        save_json_file(
            SEMGREP_REPORT,
            raw_report
        )

    # Semgrep normally returns 0 when no findings exist and 1 when findings exist.
    if code == 0:
        print("Semgrep: PASS")
    elif code == 1:
        print("Semgrep: FINDINGS DETECTED")
    else:
        message = (
            stderr.strip()
            or "Semgrep returned an unexpected exit code."
        )
        print("Semgrep scanner error.")
        print(message)
        record_scan_error(
            "Semgrep",
            message
        )
        return findings

    if raw_report is None:
        message = "Semgrep completed but did not return valid JSON."
        if stderr.strip():
            message += " Details: " + stderr.strip()
        print(message)
        record_scan_error(
            "Semgrep",
            message
        )
        return findings

    if not isinstance(raw_report, dict):
        message = (
            "Semgrep returned JSON, but the report format was not an object."
        )
        print(message)
        record_scan_error(
            "Semgrep",
            message
        )
        return findings

    results = raw_report.get(
        "results",
        []
    )

    if not isinstance(results, list):
        message = "Semgrep JSON report is missing a valid results list."
        print(message)
        record_scan_error(
            "Semgrep",
            message
        )
        return findings

    for result in results:
        check_id = result.get(
            "check_id",
            "semgrep-rule"
        )

        raw_path = result.get(
            "path",
            "Unknown"
        )

        path = normalize_repository_path(
            repository_directory,
            raw_path
        )

        start = result.get(
            "start",
            {}
        )

        line = start.get(
            "line",
            "Unknown"
        )

        extra = result.get(
            "extra",
            {}
        )

        message = extra.get(
            "message",
            "Semgrep detected a security issue."
        )

        metadata = extra.get(
            "metadata",
            {}
        )

        raw_severity = metadata.get(
            "severity",
            "WARNING"
        )

        raw_severity = str(raw_severity).upper()

        severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }

        severity = severity_map.get(
            raw_severity,
            "MEDIUM"
        )

        recommendation = (
            "Review the Semgrep finding and modify "
            "the affected code according to the "
            "security guidance."
        )

        finding = create_finding(
            scanner="Semgrep",
            severity=severity,
            finding_type="Source Code Security Issue",
            rule=check_id,
            file_path=path,
            line=line,
            message=message,
            recommended_fix=recommendation
        )

        findings.append(finding)

    return findings


# ============================================================
# PYTHON DEPENDENCY SCAN
# ============================================================

def find_requirements_files(
    repository_directory
):
    requirements = []

    for path in repository_directory.rglob(
        "requirements*.txt"
    ):
        if any(
            ignored in path.parts
            for ignored in IGNORED_DIRECTORIES
        ):
            continue

        requirements.append(path)

    return requirements


def scan_with_pip_audit(
    repository_directory
):
    print_step(
        4,
        "DEPENDENCY SCAN - PIP-AUDIT"
    )

    findings = []

    requirements_files = (
        find_requirements_files(
            repository_directory
        )
    )

    if not requirements_files:
        print("No requirements.txt file found.")
        print("Dependency scan skipped.")
        return findings

    pip_audit_exe = find_tool_executable("pip-audit")

    if not pip_audit_exe:
        message = "pip-audit is not installed."
        print(message)
        record_scan_error(
            "pip-audit",
            message
        )
        return findings

    for requirements_file in requirements_files:
        # Check if requirements file has any non-comment, non-empty content
        try:
            req_content = requirements_file.read_text(
                encoding="utf-8",
                errors="replace"
            )
            has_deps = any(
                line.strip() and not line.strip().startswith("#")
                for line in req_content.splitlines()
            )
            if not has_deps:
                print(f"pip-audit: PASS - {requirements_file.name} (no dependencies)")
                continue
        except Exception:
            pass

        command = [
            pip_audit_exe,
            "-r",
            str(requirements_file),
            "--format",
            "json",
            "--output",
            str(PIP_AUDIT_REPORT)
        ]

        remove_old_scanner_report(PIP_AUDIT_REPORT)

        code, stdout, stderr = run_command(
            command,
            timeout=600
        )

        raw_report = load_json_file(PIP_AUDIT_REPORT)

        # Fallback to direct audit without pip dry-run if conflict occurs
        if raw_report is None:
            fallback_command = [
                pip_audit_exe,
                "-r",
                str(requirements_file),
                "--no-deps",
                "--disable-pip",
                "--format",
                "json",
                "--output",
                str(PIP_AUDIT_REPORT)
            ]
            fb_code, fb_stdout, fb_stderr = run_command(
                fallback_command,
                timeout=600
            )
            raw_report = load_json_file(PIP_AUDIT_REPORT)
            if raw_report is not None:
                code, stdout, stderr = fb_code, fb_stdout, fb_stderr

        if code == 0:
            print(
                f"pip-audit: PASS - "
                f"{requirements_file.name}"
            )

        elif code == 1 and raw_report is not None:
            print(
                f"pip-audit: VULNERABILITIES - "
                f"{requirements_file.name}"
            )

        else:
            message = (
                stderr.strip()
                or stdout.strip()
                or "pip-audit returned an unexpected exit code."
            )

            print(
                f"pip-audit: scanner error - "
                f"{requirements_file.name}"
            )
            print(message)

            record_scan_error(
                "pip-audit",
                f"{requirements_file.name}: {message}"
            )
            continue

        if raw_report is None:
            message = (
                f"pip-audit did not produce a valid JSON report "
                f"for {requirements_file.name}."
            )
            print(message)
            record_scan_error(
                "pip-audit",
                message
            )
            continue

        dependencies = raw_report.get(
            "dependencies",
            []
        )

        for dependency in dependencies:
            package_name = dependency.get(
                "name",
                "Unknown package"
            )

            package_version = dependency.get(
                "version",
                "Unknown version"
            )

            vulnerabilities = dependency.get(
                "vulns",
                []
            )

            for vulnerability in vulnerabilities:
                vulnerability_id = vulnerability.get(
                    "id",
                    "Known vulnerability"
                )

                fix_versions = vulnerability.get(
                    "fix_versions",
                    []
                )

                if fix_versions:
                    fix_text = (
                        "Upgrade "
                        f"{package_name} from "
                        f"{package_version} to a fixed "
                        "version. Recommended fixed "
                        f"versions: "
                        f"{', '.join(fix_versions)}."
                    )
                else:
                    fix_text = (
                        "Review the dependency advisory "
                        "and upgrade to a secure version "
                        "when a fixed release is available."
                    )

                finding = create_finding(
                    scanner="pip-audit",
                    severity="HIGH",
                    finding_type="Vulnerable Dependency",
                    rule=vulnerability_id,
                    file_path=str(
                        requirements_file.relative_to(
                            repository_directory
                        )
                    ).replace(
                        "\\",
                        "/"
                    ),
                    line="Dependency",
                    message=(
                        f"Package {package_name} "
                        f"{package_version} has known "
                        f"vulnerability "
                        f"{vulnerability_id}."
                    ),
                    recommended_fix=fix_text
                )

                findings.append(finding)

    return findings


# ============================================================
# FILE REPORT
# ============================================================

def create_file_summary(
    files,
    findings
):
    vulnerable_files = {}

    for finding in findings:
        file_path = finding.get(
            "file",
            "Unknown"
        )

        if file_path not in vulnerable_files:
            vulnerable_files[file_path] = []

        vulnerable_files[file_path].append(finding)

    file_results = []

    for file_path in files:
        if file_path in vulnerable_files:
            file_findings = vulnerable_files[file_path]
            highest_severity = "LOW"

            severity_order = {
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4
            }

            for finding in file_findings:
                severity = finding.get(
                    "severity",
                    "LOW"
                )

                if severity_order.get(
                    severity,
                    1
                ) > severity_order.get(
                    highest_severity,
                    1
                ):
                    highest_severity = severity

            file_results.append({
                "file": file_path,
                "status": "VULNERABLE",
                "severity": highest_severity,
                "issues": len(file_findings)
            })

        else:
            file_results.append({
                "file": file_path,
                "status": "PASS",
                "severity": "NONE",
                "issues": 0
            })

    return file_results


# ============================================================
# FINAL REPORT
# ============================================================

def build_final_report(
    repository_url,
    repository_directory,
    findings,
    files,
    directory_count
):
    severity_summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "MEDIUM"
        )

        if severity in severity_summary:
            severity_summary[severity] += 1

    if SCAN_ERRORS:
        security_gate = "SCAN ERROR"
        scan_status = "FAILED"

    elif findings:
        security_gate = "BLOCKED"
        scan_status = "COMPLETED"

    else:
        security_gate = "PASS"
        scan_status = "COMPLETED"

    file_summary = create_file_summary(
        files,
        findings
    )

    report = {
        "project": "SecureCI",
        "repository": repository_url,
        "scan_time": datetime.now().strftime("%d %b %Y, %I:%M %p"),
        "scan_status": scan_status,
        "security_gate": security_gate,
        "scanner_status": {
            "status": "FAILED" if SCAN_ERRORS else "COMPLETED",
            "errors": list(SCAN_ERRORS)
        },
        "total_vulnerabilities": len(findings),
        "severity_summary": severity_summary,
        "repository_summary": {
            "files_scanned": len(files),
            "folders_scanned": directory_count,
            "vulnerable_files": len({
                finding.get("file", "Unknown")
                for finding in findings
            })
        },
        "file_summary": file_summary,
        "findings": findings
    }

    save_json_file(
        FINAL_REPORT,
        report
    )

    return report


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results(report):
    print_header("SECURECI SCAN RESULTS")

    print(
        f"Files scanned: "
        f"{report['repository_summary']['files_scanned']}"
    )

    print(
        f"Folders scanned: "
        f"{report['repository_summary']['folders_scanned']}"
    )

    print(
        f"Vulnerable files: "
        f"{report['repository_summary']['vulnerable_files']}"
    )

    print()

    print(
        f"Total vulnerabilities: "
        f"{report['total_vulnerabilities']}"
    )

    print(
        f"CRITICAL: "
        f"{report['severity_summary']['CRITICAL']}"
    )

    print(
        f"HIGH: "
        f"{report['severity_summary']['HIGH']}"
    )

    print(
        f"MEDIUM: "
        f"{report['severity_summary']['MEDIUM']}"
    )

    print(
        f"LOW: "
        f"{report['severity_summary']['LOW']}"
    )

    print()

    print(
        f"SECURITY GATE: "
        f"{report['security_gate']}"
    )

    print()

    if report.get("scanner_status", {}).get("errors"):
        print_header("SECURITY SCAN ERROR")

        for error in report["scanner_status"]["errors"]:
            print(
                f"{error['scanner']}: {error['message']}"
            )

        print()
        print("Security Gate: SCAN ERROR")

    elif report["findings"]:
        print_header("VULNERABLE FILES")

        for number, finding in enumerate(
            report["findings"],
            start=1
        ):
            print(
                f"{number}. "
                f"{finding['severity']} - "
                f"{finding['scanner']}"
            )

            print(
                f"   File: "
                f"{finding['file']}"
            )

            print(
                f"   Line: "
                f"{finding['line']}"
            )

            print(
                f"   Issue: "
                f"{finding['message']}"
            )

            print(
                f"   Fix: "
                f"{finding['recommended_fix']}"
            )

            print()

    else:
        print_header("SECURECI RESULT")
        print("No vulnerabilities detected.")
        print("Security Gate: PASS")

    print()
    print("Report generated:")
    print(FINAL_REPORT)


# ============================================================
# MAIN SCAN
# ============================================================

def scan_repository(
    repository_url
):
    ensure_report_directory()
    reset_scan_state()

    if not validate_github_url(repository_url):
        print()
        print("Invalid GitHub repository URL.")
        print("Example:")
        print("https://github.com/user/project")
        return False

    print_header("SECURECI DEVSECOPS SECURITY SCANNER")

    print("Repository:")
    print(repository_url)

    temporary_directory = tempfile.mkdtemp(
        prefix="secureci_"
    )

    repository_directory = (
        Path(temporary_directory)
        / "repository"
    )

    try:
        # STEP 1 - CLONE
        print_step(
            1,
            "REPOSITORY CHECK"
        )

        cloned = clone_repository(
            repository_url,
            repository_directory
        )

        if not cloned:
            return False

        # DISCOVER FILES
        print()
        print("Discovering repository files...")

        files = discover_files(repository_directory)
        directory_count = count_directories(repository_directory)

        print(f"Files discovered: {len(files)}")
        print(f"Folders discovered: {directory_count}")

        # SECURITY SCANNERS
        all_findings = []

        gitleaks_findings = scan_with_gitleaks(repository_directory)
        all_findings.extend(gitleaks_findings)

        semgrep_findings = scan_with_semgrep(repository_directory)
        all_findings.extend(semgrep_findings)

        pip_findings = scan_with_pip_audit(repository_directory)
        all_findings.extend(pip_findings)

        # FINAL REPORT
        print_step(
            5,
            "BUILD SECURITY REPORT"
        )

        report = build_final_report(
            repository_url,
            repository_directory,
            all_findings,
            files,
            directory_count
        )

        display_results(report)

        return not SCAN_ERRORS

    finally:
        try:
            shutil.rmtree(
                temporary_directory,
                ignore_errors=True
            )
        except Exception:
            pass


# ============================================================
# AUTOMATIC DASHBOARD START
# ============================================================

def start_dashboard():
    dashboard_url = "http://127.0.0.1:5000"

    import webbrowser

    if is_dashboard_running():
        print()
        print("=" * 65)
        print("SECURECI DASHBOARD IS ALREADY RUNNING")
        print("=" * 65)
        print()
        print(f"Dashboard URL: {dashboard_url}")
        print("Opening in default browser...")
        print()
        webbrowser.open(dashboard_url)
        return True

    print()
    print_header("STARTING SECURECI DASHBOARD")

    dashboard_file = (
        BASE_DIRECTORY
        / "app"
        / "app.py"
    )

    if not dashboard_file.exists():
        print()
        print("ERROR: Dashboard file not found.")
        print(f"Expected location: {dashboard_file}")
        print()
        return False

    try:
        import time

        print("Starting Flask dashboard...")

        py_exe = get_python_executable()

        dashboard_process = subprocess.Popen(
            [
                py_exe,
                str(dashboard_file)
            ],
            cwd=str(BASE_DIRECTORY)
        )

        # Give Flask time to start.
        time.sleep(2)

        print()
        print("Dashboard started successfully.")
        print("Opening:")
        print(dashboard_url)

        webbrowser.open(dashboard_url)

        print()
        print_header("SECURECI IS RUNNING")
        print("Security scan completed.")
        print()
        print("Dashboard:")
        print(dashboard_url)
        print()
        print("Keep this terminal open while using SecureCI.")
        print("Press CTRL+C to stop SecureCI.")
        print()

        try:
            dashboard_process.wait()
        except KeyboardInterrupt:
            print()
            print("Stopping SecureCI dashboard...")
            try:
                dashboard_process.terminate()
            except Exception:
                pass
            print("SecureCI stopped.")

        return True

    except Exception as error:
        print()
        print("ERROR: Could not start SecureCI dashboard.")
        print(f"Details: {error}")
        print()
        return False


# ============================================================
# PROGRAM START
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="SecureCI GitHub repository security scanner."
    )

    parser.add_argument(
        "--repo-url",
        dest="repo_url",
        help="Public GitHub repository URL to scan."
    )

    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Scan only. Do not start the Flask dashboard."
    )

    args = parser.parse_args()

    repository_url = (
        args.repo_url.strip()
        if args.repo_url
        else input("Enter public GitHub repository URL: ").strip()
    )

    if not repository_url:
        print("Repository URL is required.")
        return 2

    scan_success = scan_repository(repository_url)

    if scan_success and not args.no_dashboard:
        start_dashboard()

    return 0 if scan_success else 1


if __name__ == "__main__":
    sys.exit(main())
