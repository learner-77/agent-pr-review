import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Tuple


@dataclass
class Finding:
    file_path: str
    line_number: int
    category: str
    rule_name: str
    matched_text: str
    line_preview: str


# Rules are intentionally broad to flag potentially risky code.
SCAN_RULES: List[Tuple[str, str, re.Pattern[str]]] = [
    (
        "Hardcoded Secret",
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "Hardcoded Secret",
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "Hardcoded Secret",
        "Generic API/Secret Token Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
    (
        "Credential",
        "Username/Password Pair",
        re.compile(
            r"(?i)\b(?:user(name)?|login)\b\s*[:=]\s*['\"][^'\"]+['\"].{0,120}\b(?:pass(word|wd)?)\b\s*[:=]\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "Credential",
        "Password Assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    ),
    (
        "Database Connection",
        "Database URI",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|sqlserver|redis|oracle|sqlite):\/\/[^\s'\"<>]+"
        ),
    ),
    (
        "Database Connection",
        "JDBC Connection String",
        re.compile(r"(?i)\bjdbc:(?:mysql|postgresql|sqlserver|oracle):\/\/[^\s'\"<>]+"),
    ),
    (
        "Database Connection",
        "Server/Host with DB User and Password",
        re.compile(
            r"(?i)\b(?:db[_-]?host|database[_-]?host|server)\b.*\b(?:db[_-]?user|user(name)?)\b.*\b(?:db[_-]?pass|password|passwd|pwd)\b"
        ),
    ),
]


SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".swift",
    ".kt",
    ".scala",
    ".rs",
    ".sql",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".toml",
    ".xml",
    ".txt",
    ".md",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
}


def is_probably_text(file_path: Path) -> bool:
    if file_path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        with file_path.open("rb") as f:
            sample = f.read(2048)
        if b"\x00" in sample:
            return False
        return True
    except OSError:
        return False


def sanitize_snippet(value: str, max_len: int = 120) -> str:
    cleaned = value.strip().replace("\t", " ")
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


def scan_file(file_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for category, rule_name, pattern in SCAN_RULES:
                    match = pattern.search(line)
                    if match:
                        findings.append(
                            Finding(
                                file_path=str(file_path),
                                line_number=line_number,
                                category=category,
                                rule_name=rule_name,
                                matched_text=sanitize_snippet(match.group(0), 80),
                                line_preview=sanitize_snippet(line),
                            )
                        )
    except OSError:
        pass
    return findings


def walk_target_directory(target: Path) -> List[Path]:
    files: List[Path] = []
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            file_path = Path(root) / filename
            if is_probably_text(file_path):
                files.append(file_path)
    return files


def generate_report(
    target_dir: Path, files_scanned: int, findings: List[Finding], report_path: Path
) -> None:
    category_counts = {}
    for finding in findings:
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

    with report_path.open("w", encoding="utf-8") as report:
        report.write("Security Scan Summary Report\n")
        report.write("=" * 60 + "\n")
        report.write(f"Scan time: {datetime.now().isoformat(timespec='seconds')}\n")
        report.write(f"Target directory: {target_dir}\n")
        report.write(f"Files scanned: {files_scanned}\n")
        report.write(f"Total findings: {len(findings)}\n\n")

        report.write("Findings by Category\n")
        report.write("-" * 60 + "\n")
        if category_counts:
            for category, count in sorted(category_counts.items(), key=lambda x: x[0]):
                report.write(f"{category}: {count}\n")
        else:
            report.write("No issues detected by current rules.\n")
        report.write("\n")

        report.write("Detailed Findings\n")
        report.write("-" * 60 + "\n")
        if not findings:
            report.write("No suspicious patterns found.\n")
            return

        for idx, finding in enumerate(findings, start=1):
            report.write(f"[{idx}] {finding.category} - {finding.rule_name}\n")
            report.write(f"File: {finding.file_path}\n")
            report.write(f"Line: {finding.line_number}\n")
            report.write(f"Matched: {finding.matched_text}\n")
            report.write(f"Code: {finding.line_preview}\n")
            report.write("-" * 60 + "\n")


def prompt_for_directory() -> Path:
    while True:
        user_input = input("Enter directory path to scan: ").strip().strip('"')
        if not user_input:
            print("Please enter a valid directory path.")
            continue
        target_dir = Path(user_input).expanduser().resolve()
        if target_dir.exists() and target_dir.is_dir():
            return target_dir
        print("Directory not found. Try again.")


def main() -> None:
    print("Simple Security Scanner")
    print("Scans for hardcoded keys, credentials, and DB connection strings.\n")

    target_dir = prompt_for_directory()
    print(f"\nScanning: {target_dir}")

    files = walk_target_directory(target_dir)
    findings: List[Finding] = []
    for file_path in files:
        findings.extend(scan_file(file_path))

    report_path = Path.cwd() / "security_scan_report.txt"
    generate_report(target_dir, len(files), findings, report_path)

    print(f"Scan complete. Files scanned: {len(files)}")
    print(f"Findings: {len(findings)}")
    print(f"Report written to: {report_path}")


if __name__ == "__main__":
    main()
