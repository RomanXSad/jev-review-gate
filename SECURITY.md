# Security

## Report a vulnerability

[Open an issue](https://github.com/RomanXSad/jev-review-gate/issues/new). Leave out live tokens, private keys, and customer diffs.

## What this action handles

The action sends a unified diff to TypeSafe Jev. A path or added line that matches a deterministic secret rule fails the gate and is not uploaded. That scan is not a substitute for keeping secrets out of git.

`TYPESAFE_API_KEY` belongs in the calling repository's Actions secrets. Exempt logins belong in `REVIEW_GATE_EXEMPT_ACTORS` there too. Neither value belongs in a commit.

A workflow that runs on `pull_request` from forks can expose secrets to untrusted code. The example workflow is `push` and `workflow_dispatch` only. Keep it that way unless fork runs cannot read the key.

`REVIEW_GATE_ENABLED=false` skips both Jev and the secret scan. Use it only when you mean to publish without either check.
