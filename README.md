# Limitless Library

Limitless Library is verified reuse infrastructure for AI agents. This public
local alpha lets an agent ask before material work whether one permissioned,
compatible prior result can be reused. It returns one exact component, one
source-free method, or a non-disclosing abstention.

For exact reuse, the receiver—not the capsule—chooses installation paths and
verification programs. Limitless installs content-addressed bytes without
overwriting receiver files, runs the digest-bound receiver checks in a
no-network/read-only Bubblewrap sandbox, proves runtime invocation, and writes
an append-only adoption receipt.

This is a pre-alpha reference implementation. It is intentionally local,
single-operator, and Linux-only for contained verification. It is not a hosted
registry, remote trust system, package manager, or claim that technical
integration equals product adoption.

## What is open here

- JSON Schemas for capsules, queries, decisions, receiver recipes, verifier
  results, and adoption receipts.
- A source-minimized local catalog with policy and compatibility checks.
- Exact-byte, no-overwrite installation with rollback on failure.
- Receiver-owned adherence and obligation verification under Bubblewrap.
- Python embedding and bounded stdio MCP 2026-07-28 connector surfaces.
- Authoring/sealing commands, a conformance fixture, and tests.

The intended commercial boundary—hosted private catalogs, organization
identity and policy, managed verification, enterprise connectors, and
organization-wide reuse intelligence—is described in
[Open-source boundary](docs/OPEN-SOURCE-BOUNDARY.md).

## Requirements

- Python 3.11 or newer.
- Bubblewrap (`bwrap`) on Linux for exact-adoption verification.

There is deliberately no unsandboxed verifier fallback. Querying and method
selection work without Bubblewrap; exact adoption fails closed if containment
is unavailable.

## Install from this checkout

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Ten-minute local proof

Validate the public example catalog and observe all three outcomes:

```bash
limitless validate-catalog --catalog examples/catalog

limitless query \
  --catalog examples/catalog \
  --request examples/requests/exact-python.json

limitless query \
  --catalog examples/catalog \
  --request examples/requests/method-portable.json

limitless query \
  --catalog examples/catalog \
  --request examples/requests/abstain.json
```

Exercise the complete exact-adoption lifecycle in a disposable receiver:

```bash
demo_dir=$(mktemp -d)
cp -R examples/receiver "$demo_dir/receiver"

limitless query \
  --catalog examples/catalog \
  --request examples/requests/exact-python.json \
  --output "$demo_dir/decision.json"

limitless adopt \
  --catalog examples/catalog \
  --decision "$demo_dir/decision.json" \
  --recipe "$demo_dir/receiver/recipe.json" \
  --receiver "$demo_dir/receiver" \
  --receipt "$demo_dir/adoption.json" \
  --owner-authorized
```

The receiver now contains `_vendor/greeting.py`; `adoption.json` binds the
decision, recipe, exact installed bytes, receiver state, verifier bytes and
results, containment profile, and explicit operator authorization.

## MCP

Start the local stdio server:

```bash
limitless-mcp --catalog examples/catalog
```

It exposes one tool, `limitless_query_before_work`, and supports stateless MCP
`2026-07-28` requests plus the legacy `2025-03-26` initialization flow. MCP is
a bounded decision channel, not an artifact transport. Installation remains an
explicit receiver-local operation.

Python callers can use `query_local(...)` or `McpStdioConnector`; see
[Protocol](docs/PROTOCOL.md).

## Authoring

The checked-in `examples/authoring` records omit derived digests. Seal them
only after payload and receiver verifier review:

```bash
limitless seal-capsule \
  --draft examples/authoring/capsule.draft.json \
  --root examples/catalog/hello-component \
  --output capsule.json

limitless seal-recipe \
  --draft examples/authoring/recipe.draft.json \
  --receiver examples/receiver \
  --output recipe.json
```

Outputs are immutable: the commands refuse to overwrite an existing path.

## Security and project status

Read [Trust model](docs/TRUST-MODEL.md) before using the alpha. Please report
security issues according to [SECURITY.md](SECURITY.md). The schemas and
interfaces may change incompatibly before `0.1.0` stable.

Apache-2.0 licensed. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
