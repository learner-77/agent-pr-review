# Agent PR Reviewer
## Few Points
- Created using Cursor (VSC fork, free tier with auto)
- Cursor works with agentic loop directly inside the IDE.
- Claude Code uses agentic loop (sophisticated) but outside any IDE. purely like a bash script
- GH Copilot is primairly a VSC Extension (I know supports other IDE but VSC is the top priority), uses Extension Hosting + Its own pipeline. Catching up with Copilot cli

## Design
- You can leverage existing scripts for scan,repeatative tasks and package them into SKILLS to be used by AI
- SKILL.md - once packaged, can be used by human, or AI custom Agents or directly the native AI (like Cursor, GHCopilot)
- Think SKILLS and then Agents (build only when needed). All AI tools have started having their built-in agents like explore,bash so augment your AI design using skills first.

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
