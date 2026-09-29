# Contributing

Issues and pull requests are welcome. The gate is small on purpose: one exit code, your questions, and a diff.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Python 3.11 or newer. Tests stay offline. A change to `scripts/review_gate.py` or `rules/` needs a test in `tests/test_review_gate.py`.

## Add a rule

Choice, score, and uncertainty questions go in `rules/jev/<id>.yml`. Path and added-line patterns go in `rules/deterministic/<id>.yml`. The combiner reads `fail_on` locally and does not send it to Jev.

An empty rules directory fails the gate. Do not raise `max_diff_chars` above 84000. A dense diff past that size is rejected by Jev's token budget.

## Pull requests

Describe the behavior change and the test you ran. Leave secrets, customer diffs, and API keys out of the patch and the description.
