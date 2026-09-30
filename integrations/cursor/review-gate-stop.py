#!/usr/bin/env python3
"""If a push is still waiting on the review gate, ask Cursor to continue the turn."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    payload = json.load(sys.stdin)
    if payload.get("status") != "completed":
        print("{}")
        return 0

    roots = payload.get("workspace_roots") or ["."]
    marker = None
    for root in roots:
        candidate = Path(root) / ".cursor" / "runtime" / "review-gate-pending.json"
        if candidate.is_file():
            marker = candidate
            break
    if marker is None:
        here = Path(".cursor/runtime/review-gate-pending.json")
        if here.is_file():
            marker = here
    if marker is None:
        print("{}")
        return 0

    data = json.loads(marker.read_text(encoding="utf-8"))
    sha = data.get("sha") or "the pushed commit"
    json.dump(
        {
            "followup_message": (
                f"The review gate for commit {sha} has not been consumed. "
                "Run `bash scripts/wait_review_gate.sh`. Do not end the turn "
                "before it exits. On failure, show the report in "
                ".cursor/runtime/review-report/review-report.json: each failed "
                "rule, Jev's choice or score, and the diff range. The protected "
                "job did not run. A later commit is reviewed from the last success, "
                "so a partial fix is judged with what remains. When the failed "
                "rule is change-risk, name which pass-bar item is missing: a "
                "commit message that states the new behavior, docs in the diff "
                "that agree with it, or a test that asserts it. A "
                "critical-module change with all three can pass. Ask whether to "
                "add the missing item and recommit, set REVIEW_GATE_ENABLED to "
                "false to run the protected job without Jev, or stop. Do not "
                "edit code until they choose. On success, tell them the "
                "protected job was allowed to start."
            )
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
