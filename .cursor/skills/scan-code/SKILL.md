---
name: scane-code
description: Given a folder path,scans the path for any vulnerability using python script
---

# Scan Code Skill

Use this skill when a user asks to scan code for security issues.

## Behavior

- If the user gives a directory path directly, run the scanner with that path immediately (do not ask for the path again).
- Preferred scanner command:
  - `python "D:\Arindam Workspace\agent-pr-reviewer\security_scan_report.py"` and provide the path through stdin.
- Example (PowerShell):
  - `"<PATH_TO_SCAN>" | python "D:\Arindam Workspace\agent-pr-reviewer\security_scan_report.py"`

## Output Handling

- After scan completion, read `security_scan_report.txt`.
- Return a short summary:
  - target path
  - files scanned
  - total findings
  - top finding categories
- If report file is missing, surface the command output and the failure reason.
