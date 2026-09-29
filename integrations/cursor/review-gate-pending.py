#!/usr/bin/env python3
"""After a successful git push, mark the commit so the stop hook keeps the agent waiting."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

PUSH = re.compile(r"(^|[;&|]\s*)git\s+push\b")
DRY_RUN = re.compile(r"\s--dry-run\b")


def push_failed(tool_output) -> bool:
    if tool_output is None:
        return False
    data = tool_output
    if isinstance(tool_output, str):
        try:
            data = json.loads(tool_output)
        except json.JSONDecodeError:
            text = tool_output.lower()
            return "rejected" in text or "failed to push" in text
    if isinstance(data, dict):
        for key in ("exitCode", "exit_code"):
            if key in data and data[key] not in (0, "0", None):
                return True
        text = f"{data.get('stdout', '')}\n{data.get('stderr', '')}".lower()
        return "rejected" in text or "failed to push" in text
    return False


def main() -> int:
    payload = json.load(sys.stdin)
    tool_input = payload.get("tool_input") or {}
    command = ""
    if isinstance(tool_input, dict):
        command = str(tool_input.get("command") or "")
    if not command:
        command = str(payload.get("command") or "")
    if not PUSH.search(command) or DRY_RUN.search(command):
        return 0
    if push_failed(payload.get("tool_output")):
        return 0

    cwd = Path(payload.get("cwd") or ".").resolve()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode != 0:
        return 0
    sha = head.stdout.strip()
    marker_dir = cwd / ".cursor" / "runtime"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = {
        "sha": sha,
        "branch": branch.stdout.strip() if branch.returncode == 0 else "",
    }
    (marker_dir / "review-gate-pending.json").write_text(
        json.dumps(marker) + "\n", encoding="utf-8"
    )
    json.dump(
        {
            "additional_context": (
                f"git push succeeded for {sha}. Do not end this turn until "
                "`bash scripts/wait_review_gate.sh` exits. It waits for the "
                "GitHub job review-gate on this commit. If it fails, read only "
                ".cursor/runtime/review-report/review-report.json, show the "
                "failed rules, and ask the user what to do. Do not edit code "
                "first. If it passes, say the protected job was allowed to start."
            )
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
