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

This is a pre-alpha reference implementation and the inspectable foundation of
the Limitless product. It is intentionally local, single-operator, and
Linux-only for contained verification. It is not a remote trust system,
package manager, or claim that technical integration equals product adoption.

## What is open here

- JSON Schemas for capsules, queries, decisions, receiver recipes, verifier
  results, and adoption receipts.
- A source-minimized local catalog with policy and compatibility checks.
- Exact-byte, no-overwrite installation with rollback on failure.
- Receiver-owned adherence and obligation verification under Bubblewrap.
- Python embedding and bounded stdio MCP 2026-07-28 connector surfaces.
- Authoring/sealing commands, a meaningful one-command demo, a conformance
  fixture, and tests.

The local implementation is useful without an account, network connection,
model API, or Limitless-operated service. Its trust and foundation commitments
are described in [Open-source foundation](docs/OPEN-SOURCE-FOUNDATION.md).

## Requirements

- Python 3.11 or newer.
- Bubblewrap (`bwrap`) on Linux for exact-adoption verification.

There is deliberately no unsandboxed verifier fallback. Querying and method
selection work without Bubblewrap; exact adoption fails closed if containment
is unavailable.

On Debian or Ubuntu, install Bubblewrap with `sudo apt-get install bubblewrap`.

## Install and run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
limitless demo
```

The demo performs useful work on a structured agent audit event: it installs a
field-name redaction component and returns a sanitized copy while preserving
non-sensitive data. It then shows all three safe outcomes:

- exact component selection, no-overwrite installation, receiver-owned
  functional checks, and proof that receiver code invoked the supplied bytes;
- source-free method guidance when exact Python bytes do not fit a JavaScript
  receiver; and
- non-disclosing abstention for an unrelated task.

Retain every decision, the installed component, and the adoption receipt for
inspection:

```bash
limitless demo --workspace ./limitless-demo
```

The command refuses to reuse an existing workspace. The redactor is
deliberately narrow: it protects configured structured field names and is not
a general scanner for secrets hidden in free text. See [Local demo](docs/LOCAL-DEMO.md)
for the evidence map and manual commands.

## Manual conformance proof

The smaller `examples/` fixture exposes each primitive separately:

```bash
limitless validate-catalog --catalog examples/catalog

limitless query \
  --catalog examples/catalog \
  --request examples/requests/exact-python.json
```

Continue with the exact installation, method, abstention, and authoring commands
in [the conformance example](examples/README.md).

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
