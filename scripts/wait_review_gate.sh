#!/usr/bin/env bash
# Poll the review-gate job for the commit recorded by the Cursor push hook.
# On failure, download review-report.json and leave it for the agent.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
MARKER="$ROOT/.cursor/runtime/review-gate-pending.json"
REPORT_DIR="$ROOT/.cursor/runtime/review-report"

if [[ ! -f "$MARKER" ]]; then
  echo "No pending review gate marker at $MARKER" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is not installed. The review-gate marker is still pending." >&2
  exit 1
fi

exec python3 - "$MARKER" "$ROOT" "$REPORT_DIR" <<'PY'
import json, subprocess, sys, time
from pathlib import Path

marker, root, report_dir = sys.argv[1:]
sha = json.loads(Path(marker).read_text(encoding="utf-8"))["sha"]
timeout_s = int(__import__("os").environ.get("REVIEW_GATE_TIMEOUT_SECONDS", "900"))
interval_s = int(__import__("os").environ.get("REVIEW_GATE_INTERVAL_SECONDS", "15"))
deadline = time.time() + timeout_s
job_name = "review-gate"

def gh(*args):
    return subprocess.run(
        ["gh", *args],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )

while time.time() < deadline:
    listed = gh(
        "run", "list",
        "--commit", sha,
        "--limit", "10",
        "--json", "databaseId,status,createdAt",
    )
    if listed.returncode != 0:
        sys.stderr.write(listed.stderr or listed.stdout or "gh run list failed\n")
        sys.exit(1)
    runs = json.loads(listed.stdout or "[]")
    runs.sort(key=lambda item: item.get("createdAt") or "", reverse=True)
    if not runs:
        time.sleep(interval_s)
        continue
    handled = False
    for run in runs:
        run_id = str(run["databaseId"])
        viewed = gh("run", "view", run_id, "--json", "jobs")
        if viewed.returncode != 0:
            sys.stderr.write(viewed.stderr or "gh run view failed\n")
            sys.exit(1)
        jobs = json.loads(viewed.stdout or "{}").get("jobs") or []
        match = next((job for job in jobs if job.get("name") == job_name), None)
        if match is None:
            continue
        conclusion = match.get("conclusion")
        if not conclusion:
            break
        handled = True
        break
    if not handled:
        time.sleep(interval_s)
        continue
    if conclusion == "success":
        Path(marker).unlink(missing_ok=True)
        print(f"review-gate passed for {sha}. The protected job is allowed to start.")
        sys.exit(0)
    logged = gh("run", "view", run_id, "--log")
    text = logged.stdout or ""
    start = text.find("REVIEW_REPORT_JSON_BEGIN")
    end = text.find("REVIEW_REPORT_JSON_END")
    Path(marker).unlink(missing_ok=True)
    if start == -1 or end == -1 or end <= start:
        sys.stderr.write(
            f"review-gate finished with {conclusion} for {sha}, "
            "and the job log has no failure report.\n"
        )
        if logged.stderr:
            sys.stderr.write(logged.stderr)
        sys.exit(1)
    sys.path.insert(0, str(Path(root) / "scripts"))
    import review_gate
    body = review_gate.extract_report_json(text)
    if not body:
        sys.stderr.write(
            f"review-gate finished with {conclusion} for {sha}, "
            "and the job log has no readable failure report.\n"
        )
        sys.exit(1)
    dest = Path(report_dir)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "review-report.json").write_text(body + "\n", encoding="utf-8")
    sys.stdout.write(body + "\n")
    sys.stderr.write(
        "\nreview-gate failed for "
        + sha
        + ". Show only the failures above and ask the user what to do.\n"
    )
    sys.exit(1)

sys.stderr.write(f"Timed out waiting for review-gate on {sha}.\n")
sys.exit(1)
PY
