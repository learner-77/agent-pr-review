# Agent PR Reviewer

## 1. Python Script for Security Scanning

This project includes a Python script, `security_scan_report.py`, for basic security-oriented code scanning.

### What it does
- Scans a target directory for likely text/code files.
- Detects potentially risky patterns such as:
  - hardcoded secrets
  - credential-like assignments
  - database connection strings
- Writes results to `security_scan_report.txt`.

### How to run manually (PowerShell)
```powershell
"D:\path\to\target" | python "D:\Arindam Workspace\agent-pr-reviewer\security_scan_report.py"
```

After execution, check:
- `security_scan_report.txt`

## 2. Enhancing the Use Case with SKILL

To make scanning reusable for an agent workflow, this repo defines a Cursor Skill at:
- `.cursor/skills/scan-code/SKILL.md`

### Why this helps
- Standardizes how the agent runs the scanner.
- Avoids repeated manual instructions.
- Enforces consistent output handling.

### Skill-driven behavior
- Accept a directory path from the user.
- Pipe the path into `security_scan_report.py`.
- Read `security_scan_report.txt`.
- Return a short summary with:
  - target path
  - files scanned
  - total findings
  - top finding categories
