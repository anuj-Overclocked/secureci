# SecureCI

## Automated DevSecOps Security Scanner

SecureCI is a local DevSecOps security scanning tool that helps developers find common security vulnerabilities in their projects before deployment.

It scans source code, detects exposed credentials, checks Python dependencies, generates a security report, and displays the results through a local web dashboard.

Developers can fix the reported issues manually and run a fresh scan to verify the changes.

**Core workflow:** Scan → Detect → Fix → Scan Again → Verify

SecureCI does not automatically modify or fix source code.

---

## Features

- Scan local project folders
- Scan public GitHub repositories
- Detect exposed secrets using Gitleaks
- Analyze source code using Semgrep
- Check Python dependencies using pip-audit
- Classify vulnerabilities by severity
- Display a Security Gate status: PASS or BLOCKED
- Generate JSON security reports
- Identify vulnerable files and code locations
- Display results through a local web dashboard
- Support GitHub Actions security workflows
- Provide a Windows setup script

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Scanner engine and backend |
| Flask | Local web dashboard |
| HTML, CSS, JavaScript | Dashboard interface |
| Git and GitHub | Version control and repository hosting |
| Gitleaks | Secret detection |
| Semgrep | Source-code security analysis |
| pip-audit | Python dependency vulnerability detection |
| GitHub Actions | CI/CD security automation |

---

## Requirements

Before installing SecureCI, ensure you have:

- Windows 10 or Windows 11
- Python 3.11 or newer
- Git installed and available in PowerShell
- An internet connection for installation and scanner updates

The setup script creates the Python virtual environment and installs the required Python dependencies and security tools.

---

# Installation and Setup

Follow these steps in order.

## Step 1: Open PowerShell

Open PowerShell or the VS Code terminal.

Move to the folder where you want to store SecureCI. For example:

```powershell
cd D:\Projects
```

You can use another folder if you prefer.

## Step 2: Clone SecureCI from GitHub

Run:

```powershell
git clone https://github.com/anujdatapro-cpu/secureci.git
```

Enter the downloaded project folder:

```powershell
cd secureci
```

This downloads the SecureCI source code to your computer.

## Step 3: Allow the setup script to run

In the same PowerShell terminal, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This allows PowerShell scripts to run in the current terminal session.

## Step 4: Run the setup script

Run:

```powershell
.\setup.ps1
```

Wait for the setup process to finish. It prepares the environment and installs the required dependencies and security tools.

## Step 5: Activate the virtual environment

Run:

```powershell
.\venv\Scripts\Activate.ps1
```

When activation succeeds, the terminal should show `(venv)` at the beginning of the command prompt.

Keep using this activated terminal for the following steps.

## Step 6: Verify the installation

Run these commands individually:

```powershell
python --version
```

```powershell
python .\local_scanner.py --help
```

```powershell
python .\github_scanner.py --help
```

Check the security tools:

```powershell
gitleaks version
```

```powershell
semgrep --version
```

```powershell
pip-audit --version
```

If these commands work, proceed to the scanning section.

---

# Scanning a Local Project

This is the recommended workflow when you want to scan code already present on your computer.

## Step 1: Prepare your project

For example, suppose your application is stored in:

```text
D:\Projects\MyApplication
```

Your project may contain files such as:

```text
MyApplication/
├── app.py
├── config.py
├── requirements.txt
└── README.md
```

Use the actual folder path of your project. The example above is only a sample.

**Important:** Run SecureCI from its own installation folder, not from inside the application being scanned.

## Step 2: Enter the local project path

Make sure your terminal is inside the SecureCI folder and the virtual environment is activated.

Run the local scanner with your project's path:

```powershell
python .\local_scanner.py --path "D:\Projects\MyApplication" --no-dashboard
```

Replace `D:\Projects\MyApplication` with the full path to your own project folder.

For example, if your project is stored on another drive, use that path instead.

The `--no-dashboard` option runs the scan without starting the dashboard automatically. It is useful when you want to check the terminal results first.

## Step 3: Wait for the scan to finish

SecureCI runs its configured scanners:

- **Gitleaks:** Searches for exposed credentials and secrets.
- **Semgrep:** Checks source code for recognized insecure patterns.
- **pip-audit:** Checks declared Python dependencies against known vulnerability information.

SecureCI collects the results and generates a security report.

## Step 4: Understand the scan result

The Security Gate displays one of these statuses:

| Status | Meaning |
|---|---|
| BLOCKED | Findings meet the configured blocking policy. Review and fix them before proceeding. |
| PASS | No findings triggered the configured blocking policy. |
| SCAN ERROR | One or more problems prevented the scan from completing as expected. Review the scanner output. |

A PASS result does not guarantee that the application is completely secure.

## Step 5: Open the dashboard

If you used `--no-dashboard`, start the dashboard separately:

```powershell
python .\app\app.py
```

Open your browser and visit:

http://127.0.0.1:5000

Keep the dashboard terminal open while using the application.

The dashboard presents the scan status, vulnerability counts, severity information, and detailed findings from the generated report.

**Note:** The dashboard reads the report generated by the scanner. Run a fresh scan before relying on the displayed results.

---

# Demonstration: BLOCKED to PASS

You can demonstrate SecureCI using a sample project containing intentionally introduced vulnerabilities.

## Step 1: Run the initial scan

Scan the sample project's folder:

```powershell
python .\local_scanner.py --path "D:\Path\To\VulnerableProject" --no-dashboard
```

Replace the example path with the actual path.

Review the findings and confirm whether the Security Gate reports BLOCKED.

## Step 2: Fix the reported issues

Open the affected files and apply the recommended fixes manually.

Examples include:

- Remove hardcoded credentials and use environment variables.
- Replace unsafe SQL query construction with parameterized queries.
- Upgrade vulnerable dependencies to compatible fixed versions.

Only make changes appropriate to the findings actually reported by SecureCI.

## Step 3: Run a fresh scan

Run the same command again, using the same project path:

```powershell
python .\local_scanner.py --path "D:\Path\To\VulnerableProject" --no-dashboard
```

SecureCI scans the updated files and dependencies again.

If no findings remain under the configured checks, the Security Gate should report PASS.

## Step 4: View the latest result

Start or refresh the dashboard at:

http://127.0.0.1:5000

Confirm that the dashboard reflects the latest scan report.

SecureCI reports vulnerabilities; the developer is responsible for fixing them.

---

# Scanning a Public GitHub Repository

SecureCI also supports scanning public GitHub repositories.

From the activated SecureCI terminal, run:

```powershell
python .\github_scanner.py --repo-url https://github.com/USER/PROJECT.git
```

Replace the example URL with the public GitHub repository you want to scan.

To scan without automatically starting the dashboard:

```powershell
python .\github_scanner.py --repo-url https://github.com/USER/PROJECT.git --no-dashboard
```

The scanner retrieves the repository, runs the configured security checks, and generates a report.

---

## Reports

SecureCI generates JSON security reports in its reports directory.

The main report is:

```text
reports/
└── vulnerability-report.json
```

The report contains the scan status, Security Gate result, severity summary, and detected findings.

The report location and available fields may depend on the scan workflow and project configuration.

---

## Project Structure

```text
secureci/
├── app/
│   ├── app.py
│   ├── templates/
│   └── static/
├── reports/
├── scans/
├── tests/
├── github_scanner.py
├── local_scanner.py
├── security_gate.py
├── requirements.txt
├── setup.ps1
└── README.md
```

- `local_scanner.py` — scans a project folder on the local computer.
- `github_scanner.py` — scans a public GitHub repository.
- `security_gate.py` — evaluates scan findings against the configured gate policy.
- `app/app.py` — runs the Flask dashboard.
- `reports/` — stores generated security reports.
- `tests/` — contains project tests.
- `setup.ps1` — prepares the Windows environment.
- `requirements.txt` — lists Python dependencies.

Additional files and directories support configuration, CI/CD workflows, scanner rules, and project documentation.

---

## Testing

Run the test suite from the SecureCI folder with the virtual environment activated:

```powershell
python -m pytest tests
```

Review the test output and confirm that the tests pass.

---

## Limitations

- Local and GitHub scanning depend on the configured scanner capabilities.
- Dependency auditing focuses on supported Python dependency information.
- Scanner results may contain false positives or miss issues outside their detection capabilities.
- SecureCI does not automatically fix source code.
- A PASS result is not a guarantee of complete security.
- Dynamic application security testing (DAST) is outside the current core scanner workflow.

---

## Future Scope

- Expanded dynamic application security testing (DAST).
- AI-assisted vulnerability explanations and remediation guidance.
- Additional language and dependency ecosystem support.
- Expanded CI/CD integrations and reporting.

---

## Responsible Use

Use SecureCI on projects you own or are authorized to assess.

Use intentionally vulnerable sample applications only for controlled educational demonstrations.

---

## License

See the `LICENSE` file for licensing terms.
