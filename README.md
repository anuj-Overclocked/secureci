# SecureCI

## Automated DevSecOps Security Scanner

SecureCI is a local DevSecOps security scanner designed to help developers inspect software repositories for security vulnerabilities before code reaches production.

SecureCI scans local project folders or public GitHub repositories using three integrated security engines:
- **Gitleaks:** Scans for hardcoded secrets, private keys, API keys, and demo credentials.
- **Semgrep:** Scans source code for security flaws (e.g. SQL Injection, command injection, insecure defaults).
- **pip-audit:** Scans Python dependencies for known CVEs and security advisories.

When a scan finishes, SecureCI compiles findings into a unified JSON report, evaluates the Security Gate, and serves an interactive dark-themed Flask dashboard.

---

## The Real Developer Workflow

SecureCI is built around the developer's feedback loop:

```
Developer's Project -> BLOCKED -> Manual Code/Dependency Fixes -> Fresh Scan -> PASS
```

1. **Clone:** Developer clones SecureCI to their workstation.
2. **Setup:** Developer runs `.\setup.ps1` to prepare the virtual environment and dependencies.
3. **Activate:** Developer activates the virtual environment via `.\venv\Scripts\Activate.ps1`.
4. **Scan:** Developer runs `python .\local_scanner.py` and enters their local project path.
5. **Inspect:** SecureCI scans the target folder, evaluates the Security Gate, and opens the dashboard (`http://127.0.0.1:5000`).
6. **Remediate:** If findings are detected, the gate shows **BLOCKED**. Developer reviews the line numbers and recommended fixes, and manually corrects the code.
7. **Verify:** Developer runs a fresh scan against the same folder. Once clean, the gate shows **PASS**.

---

## Security Gate Policy

SecureCI enforces strict policy decisions:

| Status | Meaning | Criteria |
|---|---|---|
| **BLOCKED** | Deployment blocked | One or more valid security findings (Secret Exposure, Insecure Code, or Vulnerable Dependency) were detected in the target project. |
| **PASS** | Deployment allowed | All configured scanners completed without error and zero security vulnerabilities were found. |
| **SCAN ERROR** | Scan incomplete | A required security scanner failed to run, crashed, timed out, or produced an invalid report. SecureCI never outputs a false PASS when a scan fails. |

---

## Requirements & Prerequisites

- **Operating System:** Windows 10 or Windows 11 (PowerShell 5.1+)
- **Python:** Python 3.10, 3.11, 3.12, or 3.13
- **Git:** Git for Windows
- **Gitleaks:** Installed on system PATH:
  ```powershell
  winget install --id Gitleaks.Gitleaks -e
  ```
  *(Restart terminal after installing Gitleaks)*

---

## Quick Start Installation

Open PowerShell as your standard user and run:

```powershell
# 1. Clone repository
git clone https://github.com/anujdatapro-cpu/secureci.git
cd secureci

# 2. Allow local PowerShell script execution (process scope)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Run installation setup
.\setup.ps1

# 4. Activate virtual environment
.\venv\Scripts\Activate.ps1
```

---

## Usage

### 1. Interactive Local Scan

Run:
```powershell
python .\local_scanner.py
```
When prompted:
```
Enter the full path of the project you want to scan: D:\Projects\MyApplication
```
SecureCI will discover files, run all security engines, save the report to `reports/vulnerability-report.json`, and automatically open the web dashboard.

### 2. Direct Path Argument

```powershell
python .\local_scanner.py --path "D:\Projects\MyApplication"
```

### 3. Terminal-Only Scan (No Dashboard)

```powershell
python .\local_scanner.py --path "D:\Projects\MyApplication" --no-dashboard
```

### 4. Interactive SecureCI Runner

```powershell
python .\secureci.py
```

### 5. Scan a Remote GitHub Repository

```powershell
python .\github_scanner.py --repo-url https://github.com/pallets/flask.git
```

---

## Dashboard

The web dashboard is served locally at:
```
http://127.0.0.1:5000
```

Features:
- **Security Gate Orbit:** Visual indicator of PASS, BLOCKED, or SCAN ERROR.
- **Metric Cards:** Total findings, Critical, High, Medium, and Low counts.
- **Engine Status:** Live status indicators for Gitleaks, Semgrep, and pip-audit.
- **Detailed Findings:** Rule IDs, relative file paths, line numbers, descriptions, and actionable remediation instructions.
- **Live Rescan:** Click "Rescan" to re-evaluate the repository after editing your files.

---

## Project Structure

```
secureci/
├── app/
│   ├── app.py                     # Flask dashboard application and rescan route
│   ├── static/style.css           # Premium dark theme dashboard stylesheet
│   └── templates/
│       ├── dashboard.html         # Main security dashboard UI template
│       └── index.html             # Pipeline overview template
├── reports/
│   ├── vulnerability-report.json  # Latest combined security scan report
│   ├── gitleaks-report.json       # Gitleaks engine output
│   ├── semgrep-report.json        # Semgrep engine output
│   ├── pip-audit-report.json      # pip-audit engine output
│   └── security-status.json       # Security gate evaluation output
├── tests/
│   └── test_app.py                # Unit and integration test suite
├── .gitleaks.toml                 # Gitleaks rule configuration
├── semgrep-rules.yml              # Local Semgrep security rules
├── local_scanner.py               # Local project folder scanner CLI
├── github_scanner.py              # GitHub scanner and core security engines
├── secureci.py                    # Interactive SecureCI launcher
├── security_gate.py               # Security Gate validation utility
├── requirements.txt               # Python package dependencies
├── setup.ps1                      # Windows automated installation script
└── README.md                      # Documentation
```

---

## Troubleshooting & Limitations

- **"Semgrep is not installed" or "pip-audit is not installed":**
  Ensure the virtual environment is activated (`.\venv\Scripts\Activate.ps1`) or rerun `.\setup.ps1`. SecureCI automatically searches `venv/Scripts` as a fallback.
- **"Gitleaks is not installed":**
  Install Gitleaks via `winget install --id Gitleaks.Gitleaks -e` and restart PowerShell.
- **Dashboard Port 5000 Already in Use:**
  If port 5000 is already active, SecureCI detects it and opens the browser without crashing.
- **Conflicting Legacy Dependencies:**
  pip-audit automatically falls back to pinned requirement resolution (`--no-deps --disable-pip`) if dry-run dependency resolution encounters peer version conflicts.
- **Third-Party Folders:**
  Virtual environments (`venv`, `.venv`), `node_modules`, `__pycache__`, and `.git` folders are automatically excluded from scanning to prevent false positives and long scan times.
