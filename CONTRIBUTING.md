# Contributing

Limitless Library is pre-alpha. Small changes that preserve the fail-closed
trust model are easiest to review.

1. Open an issue describing the receiver problem and the invariant affected.
2. Work in a branch and submit a focused pull request. Direct changes to `main`
   are reserved for repository administration and emergency maintenance.
3. Add or update tests, including at least one rejection case for trust-boundary
   changes.
4. Run `pytest`, `ruff check .`, `bandit -r -q src`, `pip-audit --local`,
   and `python scripts/verify-source-quickstart.py`.
5. Update the schema and protocol documentation together when changing a public
   record.
6. Never commit real receiver repositories, credentials, private catalog data,
   internal experiment evidence, or generated adoption receipts.

For source-free method authoring, begin with `examples/publication/method.json`.
Readable drafts can be converted locally with
`limitless seal-method --draft INPUT --output NEW_FILE`. The command validates
the method and writes canonical UTF-8 JSON without overwriting or publishing.
Point the publication draft at the sealed file. Method object bytes, rather than
only their parsed JSON meaning, are bound by the signed publication intent;
changing them after preparation requires a new publication operation.

Contributions are accepted under Apache-2.0. By submitting a contribution, you
represent that you have the right to license it under those terms.
