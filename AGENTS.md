# Agents

GitHub Action and local combiner for a TypeSafe Jev review gate. MIT. Author: Roman.

Jev does not merge, tag, or push. `scripts/review_gate.py` exits 0 or 1. A later job starts only when this job succeeds.

## What to read first

- `README.md` — bootstrap into another repository, and the open problems.
- `action.yml` — the composite action a caller invokes.
- `examples/deploy.yml` — the job must be named `review-gate`, and the protected job must `needs` it.
- `rules/` — starter pack. Callers copy this to `.github/review-rules`. An empty or missing pack fails closed.
- `scripts/review_gate.py` — diff selection, secret scan, what is sent to Jev, and the pass/fail combiner.

## How a push is judged

1. `successful_review_shas` lists up to 150 recent Actions runs on the branch and keeps SHAs whose job `review-gate` succeeded.
2. `resolve_base` picks the closest of those that is an ancestor of `HEAD`. If none is, `closest_green_ancestor` walks the last 40 commits, including a success from the branch this one was cut from. The parent is the base only when that walk finds nothing.
3. `read_diff` runs `git diff --unified=1 --no-ext-diff` and attaches `commit_messages` for `base..HEAD`. Jev receives both.
4. Deterministic rules in `rules/deterministic/` scan paths and added lines. A hit does not call Jev.
5. `filter_patch_for_jev` drops media, lockfiles, and file patches over `max_file_patch_chars`, then drops more files until the excerpt is under `max_diff_chars`.
6. `post_jev` POSTs `{model: jev-latest, state, questions}` to `https://api.typesafe.ai/v1/systemone`. `fail_on` is stripped before the POST and applied in `validate_jev`.

## Instructions

- Run `pip install -r requirements-dev.txt` and `pytest` after a change. Tests must stay offline.
- Do not raise `max_diff_chars` above 84000. A dense diff past Jev's 32k-token budget returns HTTP 400. Prefer another call per file batch over a larger single body. That batching is not implemented; see the README todo.
- Do not send a secret to Jev. A deterministic hit returns before `post_jev`.
- Keep the caller's gate job named `review-gate`. The base lookup and `scripts/wait_review_gate.sh` search for that job name.
- Put exempt logins in the Actions secret `REVIEW_GATE_EXEMPT_ACTORS`, not in git. That list skips only `change-risk`.
- `REVIEW_GATE_ENABLED=false` skips the secret scan as well as Jev. Do not treat it as a narrow waiver.
- Do not add `pull_request` to a workflow that holds `TYPESAFE_API_KEY` unless fork runs cannot read the secret.
- The starter `truncate_fail_globs` are `src/**`, `app/**`, and `.github/workflows/**`. Replace them when the caller keeps code elsewhere.
- Leave the patch out of `review-report.json`. The failure report is the job log between `REVIEW_REPORT_JSON_BEGIN` and `REVIEW_REPORT_JSON_END`.

## Cursor wait

Optional and only for the consuming repository. Copy `scripts/wait_review_gate.sh` and the files in `integrations/cursor/`. A terminal push or a closed chat does not wake the agent. Each machine needs its own `gh auth login`.
