# SecureCI

## Automated DevSecOps Security Scanner

SecureCI is a local DevSecOps security scanning tool designed to help developers identify common security issues in software repositories.

SecureCI can scan a public GitHub repository, analyze its files and dependencies, generate a vulnerability report, and display the results through a local web dashboard.

The developer reviews the reported vulnerabilities, fixes them manually, and can run a RESCAN to verify whether the issues have been resolved.

SecureCI does not automatically modify or fix source code.

---

## Features

- Public GitHub repository scanning
- Secret detection using Gitleaks
- Source-code security scanning using Semgrep
- Python dependency vulnerability scanning using pip-audit
- Vulnerability severity classification
- Security Gate with PASS/BLOCKED status
- Detailed vulnerability report
- Vulnerable file identification
- Local web dashboard
- RESCAN functionality
- GitHub Actions security workflows
- Windows setup script
- JSON security reports

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Scanner and backend |
| Flask | Local web dashboard |
| HTML | Dashboard interface |
| CSS | Dashboard styling |
| JavaScript | Dashboard functionality |
| Git | Version control |
| GitHub | Repository hosting |
| Gitleaks | Secret detection |
| Semgrep | Source-code security scanning |
| pip-audit | Dependency vulnerability scanning |
| GitHub Actions | CI/CD security automation |

---

## Requirements

Before installing SecureCI, make sure you have:

- Windows 10 or Windows 11
- Python 3.11 or newer
- Git
- Internet connection

The SecureCI setup script installs and verifies the required security tools.

---

## Installation

### 1. Clone the repository

Open PowerShell and run:

```powershell
# 1. Clone repository
git clone https://github.com/anujdatapro-cpu/secureci.git
