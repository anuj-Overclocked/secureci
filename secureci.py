import os
import subprocess
import sys
import time
import webbrowser


SECURECI_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_URL = "http://127.0.0.1:5000"


def get_python_executable():
    """Return the Python executable from the project venv if available, else sys.executable."""
    candidates = [
        os.path.join(SECURECI_DIRECTORY, "venv", "Scripts", "python.exe"),
        os.path.join(SECURECI_DIRECTORY, "venv", "bin", "python"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return sys.executable


def print_banner():
    print()
    print("=" * 60)
    print("                    SECURECI")
    print("             DevSecOps Security Scanner")
    print("=" * 60)
    print()


def check_scanner_files():
    required_files = [
        "local_scanner.py",
        "github_scanner.py",
        "app/app.py",
    ]

    missing_files = []

    for file_name in required_files:
        file_path = os.path.join(
            SECURECI_DIRECTORY,
            file_name
        )

        if not os.path.exists(file_path):
            missing_files.append(file_name)

    if missing_files:
        print()
        print("ERROR: Required SecureCI files are missing.")
        print()

        for file_name in missing_files:
            print("Missing:", file_name)

        return False

    return True


def get_project_path():
    print("----------------------------------------------")
    print("STEP 1 - SELECT LOCAL PROJECT")
    print("----------------------------------------------")
    print()

    project_path = input(
        "Enter local project path: "
    ).strip().strip('"')

    if not project_path:
        print()
        print("ERROR: Project path is required.")
        return None

    project_path = os.path.abspath(project_path)

    if not os.path.exists(project_path):
        print()
        print("ERROR: Project path does not exist.")
        print(project_path)
        return None

    if not os.path.isdir(project_path):
        print()
        print("ERROR: The given path is not a folder.")
        return None

    print()
    print("Project selected:")
    print(project_path)

    return project_path


def run_local_scan(project_path):
    print()
    print("----------------------------------------------")
    print("STEP 2 - SECURITY SCAN")
    print("----------------------------------------------")
    print()

    print("Scanning local project:")
    print(project_path)
    print()

    print("Starting SecureCI scanners...")
    print()

    scanner_file = os.path.join(
        SECURECI_DIRECTORY,
        "local_scanner.py"
    )

    py_exe = get_python_executable()

    try:
        result = subprocess.run(
            [
                py_exe,
                scanner_file,
                "--path",
                project_path,
                "--no-dashboard"
            ],
            cwd=SECURECI_DIRECTORY,
            text=True
        )

        print()

        if result.returncode == 0:
            print("----------------------------------------------")
            print("SecureCI security scan completed.")
            print("----------------------------------------------")
        else:
            print("----------------------------------------------")
            print("SecureCI scan finished with an error.")
            print("----------------------------------------------")

        return result.returncode

    except Exception as error:
        print()
        print("ERROR while running security scanner:")
        print(error)
        return 1


def start_dashboard():
    print()
    print("----------------------------------------------")
    print("STEP 3 - SECURECI DASHBOARD")
    print("----------------------------------------------")
    print()

    dashboard_file = os.path.join(
        SECURECI_DIRECTORY,
        "app",
        "app.py"
    )

    if not os.path.exists(dashboard_file):
        print()
        print("ERROR:")
        print("app/app.py was not found.")
        return None

    py_exe = get_python_executable()

    try:
        print("Starting SecureCI dashboard...")

        dashboard_process = subprocess.Popen(
            [
                py_exe,
                dashboard_file
            ],
            cwd=SECURECI_DIRECTORY
        )

        time.sleep(3)

        print()
        print("Dashboard started successfully.")
        print()
        print("Opening:")
        print(DASHBOARD_URL)

        webbrowser.open(DASHBOARD_URL)

        return dashboard_process

    except Exception as error:
        print()
        print("ERROR starting dashboard:")
        print(error)
        return None


def main():
    print_banner()

    print("SecureCI location:")
    print(SECURECI_DIRECTORY)
    print()

    # STEP 0
    print("----------------------------------------------")
    print("STEP 0 - SECURECI CHECK")
    print("----------------------------------------------")

    if not check_scanner_files():
        sys.exit(1)

    print()
    print("SecureCI files verified.")

    # STEP 1
    project_path = get_project_path()

    if project_path is None:
        sys.exit(1)

    # STEP 2
    scan_result = run_local_scan(project_path)

    if scan_result != 0:
        print()
        print("WARNING:")
        print("The security scan reported an error.")
        print("Dashboard will still be started for inspection.")
        print()

    # STEP 3
    dashboard_process = start_dashboard()

    if dashboard_process is None:
        sys.exit(1)

    # FINAL
    print()
    print("=" * 60)
    print("              SECURECI IS RUNNING")
    print("=" * 60)
    print()
    print("Security scan completed.")
    print()
    print("Dashboard:")
    print(DASHBOARD_URL)
    print()
    print("Keep this terminal open.")
    print()
    print("Press CTRL+C to stop SecureCI.")
    print()

    try:
        dashboard_process.wait()

    except KeyboardInterrupt:
        print()
        print("Stopping SecureCI...")

        dashboard_process.terminate()

        print("SecureCI stopped.")


if __name__ == "__main__":
    main()
