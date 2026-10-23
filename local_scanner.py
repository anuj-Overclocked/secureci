import argparse
import os
import sys
from pathlib import Path
import github_scanner


def scan_local_directory(project_directory_input):
    if not project_directory_input or not str(project_directory_input).strip():
        print()
        print("ERROR: Project path is required.")
        return None

    try:
        project_directory = Path(str(project_directory_input).strip().strip('"')).resolve()
    except Exception as error:
        print()
        print(f"ERROR: Invalid project path: {error}")
        return None

    try:
        if not project_directory.exists():
            print()
            print("ERROR: Project path does not exist.")
            print(project_directory)
            return None

        if not project_directory.is_dir():
            print()
            print("ERROR: The given path is not a folder.")
            print(project_directory)
            return None

        # Check for directory read permissions early
        try:
            os.listdir(project_directory)
        except PermissionError:
            print()
            print("ERROR: Permission denied accessing project directory:")
            print(project_directory)
            return None

    except PermissionError:
        print()
        print("ERROR: Permission denied accessing project directory:")
        print(project_directory)
        return None
    except Exception as error:
        print()
        print(f"ERROR: Cannot access project directory: {error}")
        return None

    github_scanner.ensure_report_directory()
    github_scanner.reset_scan_state()

    print()
    print("Project selected:")
    print(project_directory)

    print()
    print("=" * 65)
    print("STEP 1 - PROJECT FILE DISCOVERY")
    print("=" * 65)

    files = github_scanner.discover_files(
        project_directory
    )

    directory_count = github_scanner.count_directories(
        project_directory
    )

    print()
    print(f"Files discovered : {len(files)}")
    print(f"Folders discovered : {directory_count}")

    all_findings = []

    print()
    print("=" * 65)
    print("STEP 2 - GITLEAKS SECRET SCAN")
    print("=" * 65)

    gitleaks_findings = (
        github_scanner.scan_with_gitleaks(
            project_directory
        )
    )

    all_findings.extend(
        gitleaks_findings
    )

    print()
    print("=" * 65)
    print("STEP 3 - SEMGREP SOURCE CODE SCAN")
    print("=" * 65)

    semgrep_findings = (
        github_scanner.scan_with_semgrep(
            project_directory
        )
    )

    all_findings.extend(
        semgrep_findings
    )

    print()
    print("=" * 65)
    print("STEP 4 - PIP-AUDIT DEPENDENCY SCAN")
    print("=" * 65)

    pip_findings = (
        github_scanner.scan_with_pip_audit(
            project_directory
        )
    )

    all_findings.extend(
        pip_findings
    )

    print()
    print("=" * 65)
    print("STEP 5 - BUILD SECURITY REPORT")
    print("=" * 65)

    report = github_scanner.build_final_report(
        str(project_directory),
        project_directory,
        all_findings,
        files,
        directory_count
    )

    github_scanner.display_results(
        report
    )

    print()
    print("=" * 65)
    print("SECURECI SCAN COMPLETED")
    print("=" * 65)

    print()
    print(
        "Security Gate:",
        report["security_gate"]
    )

    return report


def main():
    parser = argparse.ArgumentParser(
        description="SecureCI Local Project Scanner"
    )

    parser.add_argument(
        "--path",
        "-p",
        dest="project_path",
        help="Local project folder path to scan."
    )

    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Scan only. Do not start the Flask dashboard."
    )

    args = parser.parse_args()

    print()
    print("=" * 65)
    print("              SECURECI LOCAL PROJECT SCANNER")
    print("=" * 65)
    print()

    project_path = (
        args.project_path.strip().strip('"')
        if args.project_path
        else input(
            "Enter the full path of the project you want to scan: "
        ).strip().strip('"')
    )

    if not project_path:
        print()
        print("ERROR: Project path is required.")
        return 1

    report = scan_local_directory(project_path)

    if report is None:
        return 1

    if not args.no_dashboard:
        print()
        print("Starting SecureCI dashboard...")
        github_scanner.start_dashboard()

    return 0 if not github_scanner.SCAN_ERRORS else 1


if __name__ == "__main__":
    sys.exit(main())
