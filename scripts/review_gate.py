#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review gate: repository rules plus a TypeSafe Jev judgment.

Exit 0 when the combiner allows jobs that depend on this one. Exit 1 when it
does not. On failure, write review-report.json with failed rules only. The
patch is never copied into that report. A diff that matches a secret rule is
not sent to Jev.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

JEV_URL = "https://api.typesafe.ai/v1/systemone"


BYPASS_HINT = (
    " The protected job stays blocked. To run it without Jev, set the Actions "
    "variable REVIEW_GATE_ENABLED to false and re-run, or run "
    "workflow_dispatch with review_gate_enabled set to false."
)


@dataclass
class Failure:
    source: str
    rule: str
    message: str
    path: str = ""
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        item = {
            "source": self.source,
            "rule": self.rule,
            "message": self.message,
        }
        if self.path:
            item["path"] = self.path
        if self.detail:
            item["detail"] = self.detail
        return item


@dataclass
class Diff:
    base: str
    head: str
    names: list[str]
    patch: str
    branch: str = ""
    commits: list[dict] = field(default_factory=list)


@dataclass
class Rules:
    policy: dict
    deterministic: list[dict] = field(default_factory=list)
    jev: list[dict] = field(default_factory=list)


class JevError(Exception):
    pass


def load_rules(root: Path) -> tuple[Rules | None, Failure | None]:
    policy_path = root / "policy.yml"
    if not policy_path.is_file():
        return None, Failure("policy", "missing-policy", "policy.yml is missing")
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    for key in ("risk_score_gte", "review_noul_gte", "max_diff_chars"):
        if key not in policy:
            return None, Failure(
                "policy", "invalid-policy", f"policy.yml is missing {key}"
            )
    deterministic = _load_dir(root / "deterministic")
    jev = _load_dir(root / "jev")
    if not deterministic and not jev:
        return None, Failure(
            "policy", "empty-rules", "No deterministic or Jev rule files"
        )
    return Rules(policy=policy, deterministic=deterministic, jev=jev), None


def _load_dir(path: Path) -> list[dict]:
    if not path.is_dir():
        return []
    loaded = []
    for file in sorted(path.glob("*.yml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        data["_file"] = file.name
        loaded.append(data)
    return loaded


def path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    return fnmatch.fnmatch(path, pattern)


def deterministic_failures(diff: Diff, rules: list[dict]) -> list[Failure]:
    failures: list[Failure] = []
    for rule in rules:
        rule_id = str(rule.get("id") or rule.get("_file"))
        message = str(rule.get("message") or rule_id)
        path_patterns = rule.get("path_patterns") or []
        patch_patterns = rule.get("patch_patterns") or []
        if not path_patterns and not patch_patterns:
            failures.append(
                Failure(
                    "deterministic",
                    rule_id,
                    f"{rule.get('_file')} has no patterns",
                )
            )
            continue
        for pattern in path_patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                failures.append(
                    Failure("deterministic", rule_id, f"Invalid pattern: {exc}")
                )
                continue
            for name in diff.names:
                if compiled.search(name):
                    failures.append(
                        Failure("deterministic", rule_id, message, path=name)
                    )
        added = _added_patch_text(diff.patch)
        for pattern in patch_patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                failures.append(
                    Failure("deterministic", rule_id, f"Invalid pattern: {exc}")
                )
                continue
            if added and compiled.search(added):
                failures.append(Failure("deterministic", rule_id, message))
    return failures


def _added_patch_text(patch: str) -> str:
    """Only lines introduced by the diff. A deleted fixture must not fail the gate."""
    added = []
    for line in patch.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return "\n".join(added)


def blocks_jev_call(failures: list[Failure]) -> bool:
    return any(item.source == "deterministic" for item in failures)


def truncation_failure(diff: Diff, policy: dict) -> Failure | None:
    max_chars = int(policy["max_diff_chars"])
    max_files = int(policy.get("max_files") or 200)
    per_file = int(policy.get("max_file_patch_chars") or 8000)
    globs = policy.get("truncate_fail_globs") or []
    sensitive = [name for name in diff.names if any(path_matches(name, g) for g in globs)]
    if len(diff.names) > max_files and sensitive:
        return Failure(
            "policy",
            "diff-too-large",
            f"{len(diff.names)} files changed, above {max_files}, including a sensitive path",
            path=sensitive[0],
        )
    excerpt, _omitted = filter_patch_for_jev(diff.patch, max_chars, per_file)
    if len(excerpt) > max_chars and sensitive:
        return Failure(
            "policy",
            "diff-truncated",
            (
                f"Diff is {len(excerpt)} characters across {len(diff.names)} files "
                f"after omitting media and oversized files, above the Jev limit of {max_chars}. "
                "Jev was not called."
            ),
            path=sensitive[0],
        )
    return None


def build_questions(jev_rules: list[dict]) -> dict:
    questions = {}
    for rule in jev_rules:
        rule_id = str(rule.get("id") or rule.get("_file"))
        for name, spec in (rule.get("questions") or {}).items():
            key = f"{rule_id}__{name}"
            question = {
                "type": spec["type"],
                "instructions": spec["instructions"],
                "criteria": spec["criteria"],
            }
            if spec.get("fail_on"):
                question["fail_on"] = list(spec["fail_on"])
            questions[key] = question
    return questions


def api_questions(questions: dict) -> dict:
    """Fields the judgment API accepts. fail_on stays local to the combiner."""
    return {
        key: {
            "type": spec["type"],
            "instructions": spec["instructions"],
            "criteria": spec["criteria"],
        }
        for key, spec in questions.items()
    }


def jev_state(diff: Diff, policy: dict) -> dict:
    max_chars = int(policy["max_diff_chars"])
    per_file = int(policy.get("max_file_patch_chars") or 8000)
    excerpt, omitted = filter_patch_for_jev(diff.patch, max_chars, per_file)
    return {
        "branch": diff.branch,
        "comparison": f"{diff.base}..{diff.head}",
        "changed_files": diff.names[:200],
        "omitted_files": omitted[:200],
        "patch_excerpt": excerpt,
        "patch_truncated": len(excerpt) > max_chars,
        "commit_messages": list(diff.commits)[:30],
    }


_MEDIA_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".bmp", ".svg",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mov", ".avi", ".mp3", ".wav",
    ".psd", ".ai", ".map",
)
_LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "poetry.lock",
    "cargo.lock",
}


def _diff_path(header: str) -> str:
    marker = " b/"
    if marker in header:
        return header.split(marker, 1)[1].strip()
    return header.strip()


def _is_blob_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name in _LOCKFILES or name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    return any(name.endswith(suffix) for suffix in _MEDIA_SUFFIXES)


def _file_sections(patch: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"(?m)^diff --git ", patch))
    if not matches:
        return [("", patch)] if patch else []
    sections = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(patch)
        header = patch[match.end():patch.find("\n", match.end())]
        sections.append((_diff_path(header), patch[match.start():end]))
    return sections


def filter_patch_for_jev(
    patch: str, max_chars: int, per_file_chars: int = 8000
) -> tuple[str, list[str]]:
    """Drop media and oversized file bodies. Jev still receives the path."""
    omitted: list[str] = []
    kept: list[tuple[str, str]] = []
    for path, section in _file_sections(patch):
        binary = "Binary files " in section and " differ" in section
        if binary or (path and _is_blob_path(path)):
            omitted.append(path or "(binary)")
            kept.append((path, f"diff --git a/{path} b/{path}\nOmitted binary or media file.\n"))
            continue
        if len(section) > per_file_chars:
            omitted.append(path or "(oversized)")
            kept.append(
                (
                    path,
                    f"diff --git a/{path} b/{path}\n"
                    f"Omitted oversized file diff ({len(section)} characters).\n",
                )
            )
            continue
        kept.append((path, section))
    while sum(len(text) for _, text in kept) > max_chars:
        largest = max(range(len(kept)), key=lambda i: len(kept[i][1]))
        path, section = kept[largest]
        if section.startswith("diff --git ") and "Omitted " in section and len(section) < 400:
            break
        label = path or "(oversized)"
        if label not in omitted:
            omitted.append(label)
        kept[largest] = (
            path,
            f"diff --git a/{path} b/{path}\n"
            f"Omitted oversized file diff ({len(section)} characters).\n",
        )
    return "".join(text for _, text in kept), omitted


def validate_jev(questions: dict, payload: dict, policy: dict) -> list[Failure]:
    answers = payload.get("answers") if isinstance(payload, dict) else None
    if not isinstance(answers, dict):
        return [Failure("jev", "invalid-response", "Jev response has no answers object")]
    failures: list[Failure] = []
    risk_limit = float(policy["risk_score_gte"])
    noul_limit = float(policy["review_noul_gte"])
    for key, spec in questions.items():
        answer = answers.get(key)
        kind = spec["type"]
        if not isinstance(answer, dict):
            failures.append(Failure("jev", key, "Missing or invalid Jev answer"))
            continue
        if kind == "score":
            score = answer.get("score")
            ceiling = _score_ceiling(spec["criteria"])
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                failures.append(Failure("jev", key, "Score is not a number"))
            elif not 0 <= float(score) <= ceiling:
                failures.append(
                    Failure("jev", key, f"Score {score} is outside 0..{ceiling}")
                )
            elif float(score) >= risk_limit:
                failures.append(
                    _jev_failure(
                        key,
                        answer,
                        f"Risk score {float(score):.2f} is at or above {risk_limit:.2f}",
                    )
                )
        elif kind == "noul":
            noul = answer.get("noul")
            if not isinstance(noul, (int, float)) or isinstance(noul, bool):
                failures.append(Failure("jev", key, "Noul is not a number"))
            elif not 0 <= float(noul) <= 1:
                failures.append(Failure("jev", key, f"Noul {noul} is outside 0..1"))
            elif float(noul) >= noul_limit:
                failures.append(
                    _jev_failure(
                        key,
                        answer,
                        f"Review probability {float(noul):.2f} is at or above {noul_limit:.2f}",
                    )
                )
        elif kind == "choice":
            choice = answer.get("choice")
            allowed = spec["criteria"]
            if not isinstance(allowed, dict) or choice not in allowed:
                failures.append(Failure("jev", key, "Choice is not an allowed value"))
            elif choice in (spec.get("fail_on") or []):
                failures.append(_jev_failure(key, answer, f"Jev chose {choice}"))
        else:
            failures.append(Failure("jev", key, f"Unknown question type {kind}"))
    return failures


def _answer_detail(answer: dict) -> dict:
    detail = {}
    for key in (
        "choice",
        "score",
        "noul",
        "confidence",
        "probabilities",
        "reason",
        "explanation",
        "rationale",
        "comment",
    ):
        if key in answer:
            detail[key] = answer[key]
    return detail


def _jev_failure(key: str, answer: dict, message: str) -> Failure:
    return Failure(
        "jev",
        key,
        _with_jev_note(answer, message),
        detail=_answer_detail(answer),
    )


def _jev_note(answer: dict) -> str:
    for key in ("reason", "explanation", "rationale", "comment"):
        value = answer.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _with_jev_note(answer: dict, message: str) -> str:
    note = _jev_note(answer)
    if note:
        return f"{message}: {note}"
    return message


def _out_of_tokens(status: int, body: str) -> bool:
    text = body.lower()
    if status in (402, 429):
        return True
    markers = (
        "out of tokens",
        "insufficient_quota",
        "insufficient quota",
        "quota exceeded",
        "credit balance",
        "payment required",
    )
    return any(marker in text for marker in markers)


def _exempt_logins() -> set[str]:
    """Logins from the Actions secret and the Actions variable of the same name.

    Either place counts. The list is not stored in the repo. Empty means nobody.
    """
    raw = ",".join(
        os.environ.get(name, "")
        for name in ("REVIEW_GATE_EXEMPT_ACTORS", "REVIEW_GATE_EXEMPT_ACTORS_VAR")
    )
    logins = set()
    for part in raw.replace(";", ",").split(","):
        login = part.strip().strip("\"'").strip().lower()
        if login:
            logins.add(login)
    return logins


def actor_skips_change_risk() -> bool:
    """True when the pushing GitHub login is listed outside the repo."""
    actor = os.environ.get("GITHUB_ACTOR", "").strip().lower()
    if not actor:
        return False
    return actor in _exempt_logins()


def rules_for_push(rules: Rules) -> Rules:
    if not actor_skips_change_risk():
        return rules
    kept = [item for item in rules.jev if str(item.get("id") or "") != "change-risk"]
    return Rules(policy=rules.policy, deterministic=rules.deterministic, jev=kept)


def bypass_reason(policy: dict | None = None) -> str:
    """Non-empty when this run must skip Jev and allow the protected job."""
    if os.environ.get("REVIEW_GATE_ENABLED", "").strip().lower() == "false":
        return "REVIEW_GATE_ENABLED is false"
    dispatch = os.environ.get("REVIEW_GATE_DISPATCH", "").strip().lower()
    if dispatch == "false":
        return "workflow_dispatch review_gate_enabled is false"
    if policy is not None and policy.get("enabled") is False:
        return "policy.yml enabled is false"
    return ""


def _score_ceiling(criteria) -> float:
    if isinstance(criteria, list) and len(criteria) > 1:
        return float(len(criteria) - 1)
    return 3.0


def post_jev(state: dict, questions: dict, api_key: str, timeout: float = 90.0) -> dict:
    body = json.dumps(
        {"model": "jev-latest", "state": state, "questions": api_questions(questions)}
    ).encode("utf-8")
    request = urllib.request.Request(
        JEV_URL,
        data=body,
        headers={
            "authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        method="POST",
    )
    print(f"Calling Jev timeout={timeout:.0f}s", flush=True)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        if _out_of_tokens(exc.code, detail):
            raise JevError(
                f"Jev is out of tokens or quota (HTTP {exc.code}).{BYPASS_HINT}"
            ) from exc
        brief = " ".join(detail.split())[:180]
        raise JevError(f"Jev request failed: HTTP {exc.code} {brief}".rstrip()) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        waited = time.monotonic() - started
        raise JevError(
            f"Jev request failed after {waited:.0f}s (limit {timeout:.0f}s): {exc}"
        ) from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JevError("Jev response is not JSON") from exc


def evaluate(diff: Diff, rules: Rules, api_key: str, client=post_jev) -> list[Failure]:
    failures = deterministic_failures(diff, rules.deterministic)
    truncated = truncation_failure(diff, rules.policy)
    if truncated:
        failures.append(truncated)
    questions = build_questions(rules.jev)
    if questions and (blocks_jev_call(failures) or truncated):
        return failures
    if not questions:
        return failures
    if not api_key:
        failures.append(
            Failure("jev", "missing-api-key", "TYPESAFE_API_KEY is not set")
        )
        return failures
    try:
        payload = client(jev_state(diff, rules.policy), questions, api_key)
    except JevError as exc:
        failures.append(Failure("jev", "provider-failure", str(exc)))
        return failures
    failures.extend(validate_jev(questions, payload, rules.policy))
    return failures


def git_output(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or b"git failed").decode(
            "utf-8", errors="replace"
        ).strip()
        raise RuntimeError(detail)
    return result.stdout.decode("utf-8", errors="replace")


def _parent(repo: Path, head: str) -> str:
    try:
        return git_output(repo, ["rev-parse", f"{head}^"]).strip()
    except RuntimeError as exc:
        raise RuntimeError(
            f"Current commit {head} has no parent to diff"
        ) from exc


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def resolve_base(repo: Path, head: str, successful_shas: list[str] | None = None) -> str:
    """Closest green review that is an ancestor of head, otherwise the parent.

    Every commit after that green review is one diff, including reviews that
    failed in between. A newer green review replaces an older one. This is
    not the default branch.
    """
    parent = _parent(repo, head)
    closest = ""
    for sha in successful_shas or []:
        if not sha or sha == head:
            continue
        if not is_ancestor(repo, sha, head):
            continue
        if not closest or is_ancestor(repo, closest, sha):
            closest = sha
    return closest or parent


def github_fetch(url: str, token: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "authorization": f"Bearer {token}",
            "accept": "application/vnd.github+json",
            "user-agent": "review-gate",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


_RUN_PAGE_SIZE = 30
_RUN_PAGE_LIMIT = 5
_HISTORY_LIMIT = 40


def _review_gate_succeeded(jobs_payload: dict) -> bool:
    for job in jobs_payload.get("jobs") or []:
        if job.get("name") == "review-gate" and job.get("conclusion") == "success":
            return True
    return False


def successful_review_shas(
    repository: str,
    branch: str,
    token: str,
    head: str,
    fetch=github_fetch,
) -> tuple[list[str], str]:
    """SHAs on this branch whose review-gate job succeeded. Empty when lookup fails."""
    if not repository or not branch or not token:
        return [], ""
    found: list[str] = []
    seen: set[str] = set()
    for page in range(1, _RUN_PAGE_LIMIT + 1):
        url = (
            "https://api.github.com/repos/"
            + repository
            + "/actions/runs?branch="
            + urllib.parse.quote(branch, safe="")
            + f"&per_page={_RUN_PAGE_SIZE}&page={page}"
        )
        try:
            payload = fetch(url, token)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            if page == 1:
                return [], str(exc)
            break
        runs = payload.get("workflow_runs") or []
        if not runs:
            break
        for run in runs:
            sha = str(run.get("head_sha") or "")
            jobs_url = str(run.get("jobs_url") or "")
            if not sha or sha == head or sha in seen or not jobs_url:
                continue
            seen.add(sha)
            try:
                jobs = fetch(jobs_url, token)
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
                continue
            if _review_gate_succeeded(jobs):
                found.append(sha)
        if len(runs) < _RUN_PAGE_SIZE:
            break
    return found, ""


def ancestor_commit_shas(repo: Path, head: str, limit: int = _HISTORY_LIMIT) -> list[str]:
    """Ancestors of head, closest first. Head itself is not included."""
    try:
        text = git_output(
            repo, ["rev-list", "--max-count", str(limit), f"{head}^"]
        )
    except RuntimeError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def review_gate_succeeded_for_sha(
    repository: str,
    sha: str,
    token: str,
    fetch=github_fetch,
) -> bool:
    """True when this commit's workflow run has a successful review-gate job."""
    url = (
        "https://api.github.com/repos/"
        + repository
        + "/actions/runs?head_sha="
        + urllib.parse.quote(sha, safe="")
        + "&per_page=10"
    )
    payload = fetch(url, token)
    for run in payload.get("workflow_runs") or []:
        jobs_url = str(run.get("jobs_url") or "")
        if not jobs_url:
            continue
        jobs = fetch(jobs_url, token)
        if _review_gate_succeeded(jobs):
            return True
    return False


def closest_green_ancestor(
    repo: Path,
    head: str,
    repository: str,
    token: str,
    fetch=github_fetch,
    limit: int = _HISTORY_LIMIT,
) -> str:
    """Newest ancestor whose review-gate succeeded. Empty when none is found.

    Used when this branch's run list has no green ancestor. A green review
    recorded on the branch this one was cut from still counts.
    """
    if not repository or not token:
        return ""
    for sha in ancestor_commit_shas(repo, head, limit):
        try:
            if review_gate_succeeded_for_sha(repository, sha, token, fetch):
                return sha
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
            continue
    return ""


def read_commit_messages(repo: Path, base: str, head: str, limit: int = 30) -> list[dict]:
    """Subjects and bodies for commits after base, up to head. Empty on failure."""
    try:
        text = git_output(
            repo,
            [
                "log",
                "--reverse",
                f"--max-count={limit}",
                "--format=%x1e%H%x1f%s%x1f%b",
                f"{base}..{head}",
            ],
        )
    except RuntimeError:
        return []
    messages = []
    for block in text.split("\x1e"):
        block = block.strip("\n")
        if not block.strip():
            continue
        parts = block.split("\x1f", 2)
        if len(parts) < 2:
            continue
        body = parts[2].strip() if len(parts) > 2 else ""
        if len(body) > 800:
            body = body[:800] + "…"
        messages.append(
            {
                "sha": parts[0].strip()[:12],
                "subject": parts[1].strip(),
                "body": body,
            }
        )
    return messages


def read_diff(repo: Path, base: str, head: str) -> Diff:
    names = [
        line
        for line in git_output(
            repo, ["diff", "--name-only", base, head]
        ).splitlines()
        if line.strip()
    ]
    patch = git_output(
        repo, ["diff", "--unified=1", "--no-ext-diff", base, head]
    )
    return Diff(
        base=base,
        head=head,
        names=names,
        patch=patch,
        commits=read_commit_messages(repo, base, head),
    )


_LOG_PREFIX = re.compile(r"^[^\t]*\t[^\t]*\t\d{4}-\d{2}-\d{2}T[0-9:.]+Z ")


def extract_report_json(log_text: str) -> str | None:
    """Pull the failure JSON out of a GitHub job log.

    Each log line is prefixed with job, step, and timestamp. Stderr lines from
    the same second can land between the JSON lines; those are dropped.
    """
    lines: list[str] = []
    inside = False
    for raw in log_text.splitlines():
        line = _LOG_PREFIX.sub("", raw)
        if "REVIEW_REPORT_JSON_BEGIN" in line:
            inside = True
            lines = []
            continue
        if "REVIEW_REPORT_JSON_END" in line:
            inside = False
            continue
        if not inside:
            continue
        stripped = line.strip()
        if stripped[:1] in '{[]}"':
            lines.append(line)
    body = "\n".join(lines).strip()
    if not body:
        return None
    try:
        json.loads(body)
    except json.JSONDecodeError:
        return None
    return body


def write_report(
    path: Path,
    head: str,
    failures: list[Failure],
    base: str = "",
    summary: str = "",
) -> None:
    document = {
        "sha": head,
        "conclusion": "fail",
        "failures": [item.as_dict() for item in failures],
    }
    if base:
        document["base"] = base
        document["comparison"] = f"{base}..{head}"
    if summary:
        document["summary"] = summary
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def emit_github(failures: list[Failure]) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["## Review gate", ""]
    for item in failures:
        where = f" ({item.path})" if item.path else ""
        lines.append(f"- `{item.rule}`{where}: {item.message}")
        if os.environ.get("GITHUB_ACTIONS"):
            text = item.message.replace("\n", " ").replace("%", "%25")
            print(f"::error title={item.rule}::{text}", flush=True)
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--rules", default=".github/review-rules")
    parser.add_argument("--output", default="review-report.json")
    parser.add_argument("--head", default=os.environ.get("REVIEW_HEAD", "HEAD"))
    parser.add_argument(
        "--ref-name",
        default=os.environ.get("REVIEW_REF_NAME", ""),
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    rules_root = Path(args.rules)
    if not rules_root.is_absolute():
        rules_root = repo / rules_root
    output = Path(args.output)
    if not output.is_absolute():
        output = repo / output

    rules, problem = load_rules(rules_root)
    head = args.head
    base = ""
    reason = bypass_reason(None if rules is None else rules.policy)
    if reason:
        output.unlink(missing_ok=True)
        print(f"Review gate disabled ({reason}). The protected job is allowed.")
        print("Jev not called")
        return 0
    try:
        if head == "HEAD":
            head = git_output(repo, ["rev-parse", "HEAD"]).strip()
        if problem or rules is None:
            failures = [problem] if problem else [
                Failure("policy", "missing-policy", "policy.yml is missing")
            ]
        else:
            repository = os.environ.get("GITHUB_REPOSITORY", "")
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
            shas, lookup_error = successful_review_shas(
                repository,
                args.ref_name,
                token,
                head,
            )
            if lookup_error:
                print(f"Prior review lookup failed, using the parent commit: {lookup_error}")
            base = resolve_base(repo, head, shas)
            if base not in shas and not lookup_error:
                walked = closest_green_ancestor(repo, head, repository, token)
                if walked:
                    base = walked
                    shas = [walked, *shas]
            span = "last success" if base in shas else "parent"
            diff = read_diff(repo, base, head)
            diff.branch = args.ref_name
            print(
                f"Reviewing branch {args.ref_name or '(unknown)'} "
                f"commit {head[:12]} from {span} {base[:12]} "
                f"({len(diff.names)} files, {len(diff.patch)} chars)"
            )
            if not diff.names and not diff.patch.strip():
                output.unlink(missing_ok=True)
                print("Review gate passed: empty diff")
                return 0
            jev_meta: dict = {}
            active_rules = rules_for_push(rules)
            actor = os.environ.get("GITHUB_ACTOR", "").strip() or "(unknown)"
            if len(active_rules.jev) != len(rules.jev):
                print(f"change-risk skipped for {actor}")
            else:
                print(
                    f"change-risk applies to {actor}; "
                    f"exempt list configured={bool(_exempt_logins())}"
                )

            def _client(state, questions, api_key):
                payload = post_jev(state, questions, api_key)
                jev_meta["called"] = True
                if isinstance(payload, dict):
                    jev_meta["usage"] = payload.get("usage")
                    jev_meta["model"] = payload.get("model")
                    jev_meta["answers"] = payload.get("answers")
                return payload

            failures = evaluate(
                diff,
                active_rules,
                os.environ.get("TYPESAFE_API_KEY", "").strip(),
                client=_client,
            )
            if jev_meta.get("called"):
                print(
                    f"Jev called model={jev_meta.get('model') or 'jev-latest'} "
                    f"usage={jev_meta.get('usage')}"
                )
                print(
                    "Jev answers="
                    + json.dumps(jev_meta.get("answers"), ensure_ascii=False)
                )
            else:
                print("Jev not called")
    except (RuntimeError, OSError, UnicodeError) as exc:
        failures = [Failure("policy", "diff-unavailable", str(exc))]
        print("Jev not called")

    if not failures:
        output.unlink(missing_ok=True)
        print("Review gate passed")
        return 0

    summary = (
        f"Review failed for {base[:12] or '?'}..{head[:12]}. "
        "The protected job did not run. The next push is judged from the last "
        "successful review, so a partial fix is still seen with what remains."
    )
    if any("REVIEW_GATE_ENABLED" in item.message for item in failures):
        summary += BYPASS_HINT
    write_report(output, head, failures, base=base, summary=summary)
    report_text = output.read_text(encoding="utf-8")
    print("REVIEW_REPORT_JSON_BEGIN")
    print(report_text.rstrip())
    print("REVIEW_REPORT_JSON_END")
    emit_github(failures)
    for item in failures:
        print(f"{item.rule}: {item.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
