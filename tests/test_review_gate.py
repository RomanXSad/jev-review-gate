"""Policy tests for the review gate. No Docker and no network."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import review_gate  # noqa: E402


def _diff(names, patch="diff --git a/a b/a\n+line\n"):
    return review_gate.Diff(base="base", head="head", names=names, patch=patch)


def _rules():
    rules, problem = review_gate.load_rules(ROOT / "rules")
    assert problem is None
    assert rules is not None
    return rules


def _passing_payload():
    allow = {"choice": "allow"}
    return {
        "answers": {
            "unsafe-migration__data_rewrite": allow,
            "prod-stub__test_default": allow,
            "check-bypass__skipped_check": allow,
            "change-risk__risk": {"score": 0.4},
            "change-risk__needs_human_review": {"noul": 0.1},
        }
    }


def test_shipped_rules_load():
    rules = _rules()
    assert rules.policy["risk_score_gte"] == 2
    assert {item["id"] for item in rules.deterministic} == {
        "private-key-names",
        "secret-paths",
    }
    assert {item["id"] for item in rules.jev} == {
        "change-risk",
        "check-bypass",
        "prod-stub",
        "unsafe-migration",
    }


def test_missing_policy_fails(tmp_path):
    rules, problem = review_gate.load_rules(tmp_path)
    assert rules is None
    assert problem is not None
    assert problem.rule == "missing-policy"


def test_empty_rules_fail(tmp_path):
    (tmp_path / "policy.yml").write_text(
        "risk_score_gte: 2\nreview_noul_gte: 0.65\nmax_diff_chars: 100\n",
        encoding="utf-8",
    )
    (tmp_path / "deterministic").mkdir()
    (tmp_path / "jev").mkdir()
    rules, problem = review_gate.load_rules(tmp_path)
    assert rules is None
    assert problem.rule == "empty-rules"


def test_secret_path_does_not_call_jev():
    rules = _rules()
    called = {"n": 0}

    def client(state, questions, api_key):
        called["n"] += 1
        return _passing_payload()

    failures = review_gate.evaluate(
        _diff(["src/.env"]), rules, "test-key", client
    )
    assert called["n"] == 0
    assert any(item.rule == "secret-paths" and item.path == "src/.env" for item in failures)


def test_private_key_name_fails():
    rules = _rules()
    failures = review_gate.evaluate(
        _diff(["ops/id_rsa"]), rules, "", lambda *args: pytest.fail("jev called")
    )
    assert any(item.rule == "private-key-names" for item in failures)


def _private_key_block() -> str:
    # Kept split so this source file does not contain the marker the gate scans for.
    return "BEGIN " + "PRIVATE KEY"


def test_private_key_block_in_patch_does_not_call_jev():
    rules = _rules()
    patch = "diff --git a/notes.txt b/notes.txt\n+-----" + _private_key_block() + "-----\n"
    failures = review_gate.evaluate(
        _diff(["notes.txt"], patch), rules, "test-key", lambda *args: pytest.fail("jev called")
    )
    assert any(item.rule == "secret-paths" for item in failures)


def test_deleted_private_key_block_does_not_fail():
    rules = _rules()
    patch = "diff --git a/notes.txt b/notes.txt\n+-----" + _private_key_block() + "-----\n"
    removed = patch.replace("\n+", "\n-", 1)
    failures = review_gate.deterministic_failures(
        _diff(["notes.txt"], removed), rules.deterministic
    )
    assert failures == []


def test_missing_api_key_fails_without_calling():
    rules = _rules()
    failures = review_gate.evaluate(
        _diff(["docs/dev/jev-review-gate.md"]),
        rules,
        "",
        lambda *args: pytest.fail("jev called"),
    )
    assert [item.rule for item in failures] == ["missing-api-key"]


def test_jev_block_choice_fails_and_keeps_the_reason():
    rules = _rules()

    def client(state, questions, api_key):
        sent = review_gate.api_questions(questions)
        assert "fail_on" not in sent["unsafe-migration__data_rewrite"]
        allow = {"choice": "allow"}
        return {
            "answers": {
                "unsafe-migration__data_rewrite": {
                    "choice": "block",
                    "reason": "The migration rewrites rows and has no reverse.",
                },
                "prod-stub__test_default": allow,
                "check-bypass__skipped_check": allow,
                "change-risk__risk": {"score": 0.2},
                "change-risk__needs_human_review": {"noul": 0.1},
            }
        }

    failures = review_gate.evaluate(
        _diff(["src/migrations/0099_rewrite.py"]), rules, "test-key", client
    )
    match = next(item for item in failures if item.rule == "unsafe-migration__data_rewrite")
    assert "Jev chose block" in match.message
    assert "no reverse" in match.message


def test_extract_report_ignores_log_prefixes_and_stderr():
    log = "\n".join(
        [
            "review-gate\tRun review gate\t2026-09-27T16:03:41.1000000Z REVIEW_REPORT_JSON_BEGIN",
            'review-gate\tRun review gate\t2026-09-27T16:03:41.2000000Z {',
            'review-gate\tRun review gate\t2026-09-27T16:03:41.2000000Z   "conclusion": "fail"',
            "review-gate\tRun review gate\t2026-09-27T16:03:41.2000000Z noise-rule: noise from stderr",
            'review-gate\tRun review gate\t2026-09-27T16:03:41.2000000Z }',
            "review-gate\tRun review gate\t2026-09-27T16:03:41.3000000Z REVIEW_REPORT_JSON_END",
        ]
    )
    document = json.loads(review_gate.extract_report_json(log))
    assert document["conclusion"] == "fail"


def test_high_risk_fails():
    failures = review_gate.validate_jev(
        {"sample__risk": {"type": "score", "criteria": ["a", "b", "c", "d"]}},
        {"answers": {"sample__risk": {"score": 2.4}}},
        {"risk_score_gte": 2, "review_noul_gte": 0.65},
    )
    assert any(item.rule == "sample__risk" for item in failures)


def test_low_risk_passes_and_sends_no_secret_body():
    rules = _rules()
    seen = {}

    def client(state, questions, api_key):
        seen["state"] = state
        seen["key"] = api_key
        return _passing_payload()

    failures = review_gate.evaluate(
        _diff(["docs/README.md"], "diff --git a/docs/README.md\n+hello\n"),
        rules,
        "test-key",
        client,
    )
    assert failures == []
    assert seen["key"] == "test-key"
    assert _private_key_block() not in seen["state"]["patch_excerpt"]


def test_invalid_jev_json_shape_fails():
    rules = _rules()
    failures = review_gate.evaluate(
        _diff(["docs/README.md"]), rules, "test-key", lambda *a: {"nope": True}
    )
    assert any(item.rule == "invalid-response" for item in failures)


def test_provider_failure_fails():
    rules = _rules()

    def client(state, questions, api_key):
        raise review_gate.JevError("Jev request failed: timed out")

    failures = review_gate.evaluate(
        _diff(["docs/README.md"]), rules, "test-key", client
    )
    assert any(item.rule == "provider-failure" for item in failures)


def test_media_and_oversized_files_are_not_sent_to_jev():
    rules = _rules()
    png = "diff --git a/docs/shot.png b/docs/shot.png\nBinary files /dev/null and b/docs/shot.png differ\n"
    big_body = "x" * (int(rules.policy["max_file_patch_chars"]) + 50)
    huge = (
        "diff --git a/src/pages/Calendar.tsx "
        "b/src/pages/Calendar.tsx\n"
        + big_body
        + "\n"
    )
    small = "diff --git a/docs/README.md b/docs/README.md\n+hello\n"
    seen = {}

    def client(state, questions, api_key):
        seen["state"] = state
        return _passing_payload()

    failures = review_gate.evaluate(
        _diff(
            ["docs/shot.png", "src/pages/Calendar.tsx", "docs/README.md"],
            png + huge + small,
        ),
        rules,
        "test-key",
        client,
    )
    assert failures == []
    excerpt = seen["state"]["patch_excerpt"]
    assert "hello" in excerpt
    assert big_body not in excerpt
    assert "Binary files" not in excerpt
    assert "docs/shot.png" in seen["state"]["omitted_files"]
    assert "src/pages/Calendar.tsx" in seen["state"]["omitted_files"]


def test_oversized_sensitive_file_is_omitted_and_jev_still_runs():
    rules = _rules()
    big = "x" * (int(rules.policy["max_diff_chars"]) + 10)
    seen = {}

    def client(state, questions, api_key):
        seen["excerpt"] = state["patch_excerpt"]
        return _passing_payload()

    failures = review_gate.evaluate(
        _diff(["src/services/payments.py"], big),
        rules,
        "test-key",
        client,
    )
    assert failures == []
    assert big not in seen["excerpt"]
    assert "Omitted oversized" in seen["excerpt"]


def test_report_contains_failures_only(tmp_path):
    report = tmp_path / "review-report.json"
    review_gate.write_report(
        report,
        "abc",
        [review_gate.Failure("deterministic", "secret-paths", "Refusing", path=".env")],
    )
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["conclusion"] == "fail"
    assert document["failures"][0]["path"] == ".env"
    assert "patch" not in document


def test_build_job_depends_on_review_gate():
    workflow = yaml.safe_load(
        (ROOT / "examples" / "deploy.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["deploy"]
    needs = job["needs"]
    assert needs == "review-gate" or needs == ["review-gate"]
    assert "needs.review-gate.result == 'success'" in job["if"]
    assert "review-gate" in workflow["jobs"]


def test_stop_hook_followup_when_pending(tmp_path):
    marker_dir = tmp_path / ".cursor" / "runtime"
    marker_dir.mkdir(parents=True)
    (marker_dir / "review-gate-pending.json").write_text(
        json.dumps({"sha": "abc123"}) + "\n", encoding="utf-8"
    )
    proc = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / "cursor" / "review-gate-stop.py")],
        input=json.dumps({"status": "completed", "loop_count": 0, "workspace_roots": [str(tmp_path)]}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    message = json.loads(proc.stdout)["followup_message"]
    assert "abc123" in message
    assert "wait_review_gate.sh" in message


def test_stop_hook_silent_without_marker(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / "cursor" / "review-gate-stop.py")],
        input=json.dumps({"status": "completed", "workspace_roots": [str(tmp_path)]}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert json.loads(proc.stdout) == {}


def test_stop_hook_silent_when_aborted(tmp_path):
    marker_dir = tmp_path / ".cursor" / "runtime"
    marker_dir.mkdir(parents=True)
    (marker_dir / "review-gate-pending.json").write_text(
        json.dumps({"sha": "abc123"}), encoding="utf-8"
    )
    proc = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / "cursor" / "review-gate-stop.py")],
        input=json.dumps(
            {"status": "aborted", "workspace_roots": [str(tmp_path)]}
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert json.loads(proc.stdout) == {}


def test_pending_hook_writes_marker(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "dev@example.com"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    proc = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / "cursor" / "review-gate-pending.py")],
        input=json.dumps(
            {
                "cwd": str(tmp_path),
                "tool_input": {"command": "git push -u origin HEAD"},
                "tool_output": {"exitCode": 0},
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    context = json.loads(proc.stdout)["additional_context"]
    assert "wait_review_gate.sh" in context
    marker = json.loads(
        (tmp_path / ".cursor" / "runtime" / "review-gate-pending.json").read_text(
            encoding="utf-8"
        )
    )
    assert marker["sha"]
    assert marker["sha"] in context


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.email=dev@example.com", "-c", "user.name=Dev", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def test_diff_starts_at_last_success_and_keeps_unfixed_changes(tmp_path):
    _git(tmp_path, "init", "-b", "dev")
    (tmp_path / "readme").write_text("ok\n", encoding="utf-8")
    _git(tmp_path, "add", "readme")
    _git(tmp_path, "commit", "-m", "dev")
    dev = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    _git(tmp_path, "checkout", "-b", "feature")
    (tmp_path / "readme").write_text("ok\n", encoding="utf-8")
    _git(tmp_path, "commit", "--allow-empty", "-m", "green")
    green = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    (tmp_path / "readme").write_text("ok\nwaive()\nlog()\n", encoding="utf-8")
    _git(tmp_path, "commit", "-am", "rejected")
    (tmp_path / "readme").write_text("ok\nwaive()\n", encoding="utf-8")
    _git(tmp_path, "commit", "-am", "partial fix")
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    parent = subprocess.check_output(
        ["git", "rev-parse", "HEAD^"], cwd=tmp_path, text=True
    ).strip()
    base = review_gate.resolve_base(tmp_path, head, [green])
    assert base == green
    assert base != parent
    assert base != dev
    diff = review_gate.read_diff(tmp_path, base, head)
    assert "waive()" in diff.patch
    assert "log()" not in diff.patch
    only_latest = review_gate.resolve_base(tmp_path, head, [])
    assert only_latest == parent


def test_last_success_lookup_skips_failed_runs_and_current_sha():
    def fetch(url, token):
        if "runs?" in url:
            assert "feature%2Fexample" in url
            assert "manual.yaml" not in url
            return {
                "workflow_runs": [
                    {"head_sha": "new", "jobs_url": "https://example/jobs/new"},
                    {"head_sha": "bad", "jobs_url": "https://example/jobs/bad"},
                    {"head_sha": "good", "jobs_url": "https://example/jobs/good"},
                ]
            }
        if url.endswith("/bad"):
            return {"jobs": [{"name": "review-gate", "conclusion": "failure"}]}
        if url.endswith("/good"):
            return {"jobs": [{"name": "review-gate", "conclusion": "success"}]}
        return {"jobs": [{"name": "review-gate", "conclusion": "success"}]}

    shas, error = review_gate.successful_review_shas(
        "org/repo", "feature/example", "token", "new", fetch
    )
    assert error == ""
    assert shas == ["good"]


def test_exempt_actor_skips_only_change_risk(monkeypatch):
    monkeypatch.setenv("REVIEW_GATE_EXEMPT_ACTORS", "octocat")
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    assert review_gate.actor_skips_change_risk()
    skipped = review_gate.rules_for_push(_rules())
    assert {item["id"] for item in skipped.jev} == {
        "check-bypass",
        "prod-stub",
        "unsafe-migration",
    }
    monkeypatch.setenv("GITHUB_ACTOR", "other-dev")
    assert review_gate.actor_skips_change_risk() is False
    rules = _rules()
    assert review_gate.rules_for_push(rules) is rules
    monkeypatch.delenv("REVIEW_GATE_EXEMPT_ACTORS")
    assert review_gate.actor_skips_change_risk() is False
    monkeypatch.setenv("REVIEW_GATE_EXEMPT_ACTORS_VAR", '"octocat"')
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    assert review_gate.actor_skips_change_risk()


def test_disable_switch_skips_the_gate(monkeypatch):
    monkeypatch.setenv("REVIEW_GATE_ENABLED", "false")
    assert "REVIEW_GATE_ENABLED" in review_gate.bypass_reason({"enabled": True})
    monkeypatch.delenv("REVIEW_GATE_ENABLED")
    assert review_gate.bypass_reason({"enabled": True}) == ""
    assert review_gate.bypass_reason({"enabled": False}) == "policy.yml enabled is false"


def test_out_of_tokens_reports_the_bypass(monkeypatch):
    import io
    import urllib.error

    def raise_http(*args, **kwargs):
        raise urllib.error.HTTPError(
            review_gate.JEV_URL,
            402,
            "Payment Required",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"quota exceeded"}'),
        )

    monkeypatch.setattr(review_gate.urllib.request, "urlopen", raise_http)
    with pytest.raises(review_gate.JevError) as caught:
        review_gate.post_jev({}, {}, "test-key")
    assert "out of tokens" in str(caught.value)
    assert "REVIEW_GATE_ENABLED" in str(caught.value)
