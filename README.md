# Jev review gate

[![Tests](https://github.com/RomanXSad/jev-review-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/RomanXSad/jev-review-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A GitHub Actions check that reads your diff, applies a few local rules, and asks [TypeSafe Jev](https://typesafe.ai) (`POST https://api.typesafe.ai/v1/systemone`, model `jev-latest`) the questions in your rule pack. The action exits 0 or 1. Jev does not merge, tag, or push. Any later job that `needs` this one stays skipped until the gate passes.

**v1.1.0.** Free to use, copy, and change under the [MIT license](LICENSE). Read the [limits](#-todo) before you treat a green run on a large diff as a full review.

Author: Roman

## 🎯 The problem

A workflow that builds or deploys on every push starts that job because the push succeeded. Nothing in the pipeline reads the diff and decides whether this change is safe to ship.

These are the changes that get through:

- A migration rewrites or deletes existing data, and the reverse is a no-op.
- Production code gains a test host, `ALLOWED_HOSTS` of `*`, a local-only secret, or a frontend bundle that calls localhost.
- A payment signature, webhook check, or auth gate is skipped outside test, or a new route runs a shell with no login.

A regex can catch a private key in the diff. It cannot tell an irreversible migration from a new nullable column, or a bypass that stays in test from one that now runs in production.

The other hole is the commit window. A branch often fails the gate more than once, and the last commit fixes only part of what the earlier commits introduced. A review of that last commit alone leaves the rest of the unsafe diff in the branch, and the protected job still ships it.

## ✨ What this brings

- The protected job starts only after this one exits 0. Jev does not merge, tag, or push.
- You write the questions. Jev answers them on the diff from the closest green `review-gate` through the current commit. Failed reviews in between stay in that diff, and the commit messages travel with the patch.
- Secret paths and key material fail locally and are not uploaded.
- A failure is a short JSON report in the job log: the rule, the choice or score, and the commit range.
- One composite action plus a rule pack you can edit. The starter pack covers unsafe migrations, production stubs, and skipped checks.

## 🚀 Add it to a repository

1. Create a TypeSafe API key and store it as the Actions secret `TYPESAFE_API_KEY`.
2. Copy [`rules/`](rules/) to `.github/review-rules` in the repository you want to gate. Edit the prompts. A missing or empty pack fails the gate.
3. Add a job that checks out the repository with full history and calls this action. Put the protected work in a second job that needs the first.

`fetch-depth: 0` is required. The gate diffs from the closest ancestor whose `review-gate` job succeeded through the current commit. Failed reviews between those commits stay in the diff. A later success moves the base forward. When this branch's own runs have no green ancestor, the gate checks the last 40 commits, including a success recorded on the branch this one was cut from. The parent commit is the base only when none of those succeeded.

```yaml
name: CI

on:
  push:
    branches:
      - "**"
  workflow_dispatch:
    inputs:
      review_gate_enabled:
        description: Run the Jev review gate. False lets the protected job start without it.
        type: boolean
        default: true

jobs:
  review-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    env:
      TYPESAFE_API_KEY: ${{ secrets.TYPESAFE_API_KEY }}
      REVIEW_GATE_EXEMPT_ACTORS: ${{ secrets.REVIEW_GATE_EXEMPT_ACTORS }}
      REVIEW_GATE_ENABLED: ${{ vars.REVIEW_GATE_ENABLED }}
      REVIEW_GATE_DISPATCH: ${{ github.event.inputs.review_gate_enabled }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: RomanXSad/jev-review-gate@v1

  deploy:
    needs: review-gate
    if: needs.review-gate.result == 'success'
    runs-on: ubuntu-latest
    steps:
      - run: echo "review-gate passed"
```

The same file is checked in as [`examples/deploy.yml`](examples/deploy.yml). Pin `@v1` for the stable line, or `@v1.1.0` for this exact release. The job that calls the action must be named `review-gate`, because later runs look up that job name when choosing the diff base.

Set the secrets and variables on the calling repository, not in this action:

| Name | Where | Effect |
|---|---|---|
| `TYPESAFE_API_KEY` | Actions secret | Sent as the bearer token. Required for a real judgment. |
| `REVIEW_GATE_EXEMPT_ACTORS` | Actions secret or variable | Comma-separated GitHub logins. Those pushes skip only the `change-risk` question. Secret checks and the other prompts still run. An empty list exempts nobody. |
| `REVIEW_GATE_ENABLED` | Actions variable | `false` skips Jev and lets the protected job run. This also skips the secret checks, so leave it unset for normal pushes. |
| `review_gate_enabled` | `workflow_dispatch` input | Same bypass for one manual run. |

`permissions: actions: read` is required. The gate lists earlier runs on the branch to find the last success.

## 📦 What the gate sends

One call per push. The body is `{ "model": "jev-latest", "state", "questions" }`. `state` carries the branch, the commit range, the path list, and a unified diff. `fail_on` and the score cutoffs stay in this repository's combiner; they are not sent.

These files are listed and their bytes are not sent:

- images, fonts, audio, video, archives, PDF, source maps, minified assets, and lockfiles
- any single file whose patch is larger than `max_file_patch_chars` (8000)
- further large files if the remainder would pass `max_diff_chars` (84000)

A diff that is still over that cap and touches `src/**`, `app/**`, or `.github/workflows/**` fails without calling Jev. Change `truncate_fail_globs` in your copied `policy.yml` when your code lives somewhere else.

A path or added line that matches a deterministic rule fails the gate and does not call Jev, so a private key is not uploaded.

## 📏 Starter rules

The pack in [`rules/`](rules/) is a starting point, not a policy for every codebase.

| Rule | Kind | Fails when |
|---|---|---|
| `secret-paths` | path and added-line patterns | `.env`, key material, `credentials.json` |
| `private-key-names` | path patterns | `id_rsa`, `id_ed25519`, `id_ecdsa`, `.pfx` |
| `unsafe-migration` | Jev choice | irreversible data rewrite, destructive column change, or a unique constraint without a dedupe |
| `prod-stub` | Jev choice | production code gains a test host, `ALLOWED_HOSTS` of `*`, a local secret, or a localhost API |
| `check-bypass` | Jev choice | a signature, webhook, or auth check is skipped on a production path |
| `change-risk` | Jev score and uncertainty | score ≥ 2, or review uncertainty ≥ 0.65. A data, auth, payment, or deploy change can score Moderate when the commit message, the docs in the diff, and a test all state the new behavior |

Choice questions live in `rules/jev/*.yml`. The local combiner treats `fail_on: [block]` as a failure. Score and uncertainty cutoffs live in `rules/policy.yml`.

## 📋 Failure report

On failure the job log contains JSON between `REVIEW_REPORT_JSON_BEGIN` and `REVIEW_REPORT_JSON_END`. The report lists failed rules, the Jev choice or score, and the commit range. It does not include the patch. The action writes that file under the runner temp directory, not into your checkout, and it does not upload an artifact.

## 🤖 Optional Cursor wait

If an agent in Cursor pushes the branch, it can wait for this job and show the report:

1. Copy `scripts/wait_review_gate.sh` into the consuming repository.
2. Copy `integrations/cursor/review-gate-pending.py` and `review-gate-stop.py` to `.cursor/hooks/`.
3. Merge the entries in `integrations/cursor/hooks.json` into `.cursor/hooks.json`. Keep any hooks you already have.
4. Ignore `.cursor/runtime/`.
5. Each machine needs `gh` and `gh auth login`. The API key stays in GitHub, not on the laptop.

The wait script looks for a job named `review-gate` on the pushed commit. It does not call Jev.

## 📝 Todo

Known gaps. None of these block copying the action into a repository. They do change how much a green run means.

- **Partial diffs false-trigger.** One Jev call can take about 84,000 characters. Larger file patches are replaced with a one-line omission, and the questions say to judge only what is shown. A safe change can look unsafe when the mitigating hunk was omitted (the dedupe, the test-only branch, the auth gate in another file). The same cut can hide the unsafe hunk and return allow. Both are properties of sending a slice, not of the full diff.
- **No second call for the files that were omitted.** Splitting the diff into batches under the token cap, and failing the gate if any batch blocks, is not built. A single source file whose patch is over about 84,000 characters still cannot be sent whole.
- **`change-risk` scores the excerpt.** The score and the uncertainty are about the text Jev received. An omitted file can make a small change look critical, or a risky file never enter the score.
- **Fail-closed globs are a starter list.** `rules/policy.yml` refuses a truncated diff when it touches `src/**`, `app/**`, or `.github/workflows/**`. A repository that keeps code elsewhere should replace those globs before relying on the size check.
- **A green review older than the lookup window is missed.** The gate reads up to 150 recent Actions runs, then walks the last 40 ancestors. Older than that, the base is the parent commit, and a failed lookup does the same after a warning.
- **The gate job name is fixed.** The base lookup and the Cursor wait script both search for a job named `review-gate`. Another name silently reviews only the parent commit.
- **The full bypass also skips secret checks.** `REVIEW_GATE_ENABLED=false` and `policy.yml` `enabled: false` do not call Jev and do not run the path rules. There is no separate "a named person approved this run" step. `REVIEW_GATE_EXEMPT_ACTORS` skips only `change-risk`.
- **Starter prompts assume a web backend.** Migrations, `ALLOWED_HOSTS`, webhook signatures, and a localhost API bundle are the examples. Other stacks need their own questions. The "if this diff does not show it clearly, allow" line keeps noise down and also lets an omitted file pass.
- **A non-200 from Jev is logged as not called.** `Calling Jev` is printed before the POST. The success line is set only after HTTP 200, so a 400 still ends with `Jev not called`.
- **This repository does not run the gate on itself.** `ci.yml` runs pytest only, so the published action is not dogfooded.

## 🛠️ Development

```bash
pip install -r requirements-dev.txt
pytest
```

Python 3.11 or newer. Tests do not call the network. Agents changing this repository should follow [AGENTS.md](AGENTS.md).

## 🤝 Community

- [Contributing](CONTRIBUTING.md) — tests, and how to add a rule
- [Security](SECURITY.md) — where to report a vulnerability, and where the API key stays
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)
