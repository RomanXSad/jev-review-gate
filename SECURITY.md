# Security

## Report a vulnerability

Email [gdeadbones@gmail.com](mailto:gdeadbones@gmail.com). Do not open a public issue for a vulnerability, and do not include a live token, a private key, or a customer diff.

## What this action handles

The action sends a unified diff to TypeSafe Jev. A path or added line that matches a deterministic secret rule fails the gate and is not uploaded. That scan is not a substitute for keeping secrets out of git.

`TYPESAFE_API_KEY` belongs in the calling repository's Actions secrets. Exempt logins belong in `REVIEW_GATE_EXEMPT_ACTORS` there too. Neither value belongs in a commit.

A workflow that runs on `pull_request` from forks can expose secrets to untrusted code. The example workflow is `push` and `workflow_dispatch` only. Keep it that way unless fork runs cannot read the key.

`REVIEW_GATE_ENABLED=false` skips both Jev and the secret scan. Use it only when you mean to publish without either check.
