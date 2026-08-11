# Contributing

Limitless Library is pre-alpha. Small changes that preserve the fail-closed
trust model are easiest to review.

1. Open an issue describing the receiver problem and the invariant affected.
2. Add or update tests, including at least one rejection case for trust-boundary
   changes.
3. Run `pytest`, `ruff check .`, `bandit -r -q src`, `pip-audit --local`,
   and the isolated quickstart.
4. Update the schema and protocol documentation together when changing a public
   record.
5. Never commit real receiver repositories, credentials, private catalog data,
   internal experiment evidence, or generated adoption receipts.

Contributions are accepted under Apache-2.0. By submitting a contribution, you
represent that you have the right to license it under those terms.
