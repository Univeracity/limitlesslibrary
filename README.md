<p align="center">
  <img src="docs/assets/limitless-library-mark.png" width="148" alt="Limitless Library mark">
</p>

<h1 align="center">Limitless Library</h1>

<p align="center"><strong>Verified reuse infrastructure for agents.</strong></p>

<p align="center">
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-111111"></a>
  <img alt="Python 3.11 or newer" src="https://img.shields.io/badge/python-3.11%2B-111111">
  <a href="docs/PROTOCOL.md"><img alt="MCP 2026-07-28" src="https://img.shields.io/badge/MCP-2026--07--28-111111"></a>
  <img alt="Pre-alpha" src="https://img.shields.io/badge/status-pre--alpha-6b7280">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-verified-reuse-works">Lifecycle</a> ·
  <a href="#mcp">MCP</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

Agents can find prior work. Finding it does not establish that it is
authorized, compatible, unchanged, or actually used.

Limitless Library lets an agent ask before material work whether one
permissioned prior result can safely cross into a receiving environment. It
returns one exact component, one source-free method, or a non-disclosing
abstention—and binds successful adoption to receiver-owned evidence.

```text
query before work → rights + fit decision → receiver-local verification
                  → observed invocation → adoption receipt
```

## At a glance

| Property | What it means |
| --- | --- |
| **Three safe outcomes** | Exact component, source-free method, or abstention |
| **Receiver-owned proof** | The receiving environment chooses installation paths and verification programs |
| **Exact bytes** | Content-addressed installation refuses overwrite and rolls back on failure |
| **Fail-closed verification** | No network, inherited secrets, or unsandboxed verifier fallback |
| **Observed use** | Delivery is not counted as reuse until receiver code invokes the supplied component |
| **Local by default** | The reference lifecycle needs no account, hosted service, or model API |

## Quick start

### Requirements

- Python 3.11 or newer.
- Linux with [Bubblewrap](https://github.com/containers/bubblewrap)
  (`bwrap`) for exact-adoption verification.

On Debian or Ubuntu:

```bash
sudo apt-get install bubblewrap
```

Create a clean environment, install the project, and run the complete local
lifecycle:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
limitless demo
```

Retain the decisions, installed component, verifier evidence, and adoption
receipt for inspection:

```bash
limitless demo --workspace ./limitless-demo
```

The command deliberately refuses an existing workspace.

### What the demo does

The bundled demo performs useful work on a structured agent audit event. It
installs a narrow field-name redaction component and returns a sanitized copy
while preserving non-sensitive data. It then demonstrates every safe outcome:

1. **Exact adoption** — installs exact bytes without overwrite, runs
   receiver-owned checks, and proves receiver code invoked the component.
2. **Method guidance** — returns a source-free method when Python bytes do not
   fit a JavaScript receiver.
3. **Safe abstention** — withholds candidate details when no result fits.

The redactor protects configured structured field names; it is not a general
scanner for secrets embedded in free text. See the
[local demo evidence map](docs/LOCAL-DEMO.md) for the generated artifacts and
manual inspection commands.

## How verified reuse works

For exact reuse, the receiver—not the capsule—controls the trust boundary:

1. A query describes the requested capability and receiving environment.
2. Policy and compatibility gates select at most one eligible result.
3. The receiver chooses the destination and provides digest-bound checks.
4. Limitless installs content-addressed bytes without overwriting receiver
   files.
5. Bubblewrap runs the checks with no network, no inherited secrets, bounded
   resources, and a read-only receiver mount.
6. Runtime evidence proves invocation and an append-only receipt binds the
   decision, component, verification, and disposition.

If exact bytes do not fit, only a source-free method may cross. If no safe
candidate exists, Limitless abstains without disclosing one.

## What is open here

- JSON Schemas for capsules, queries, decisions, receiver recipes, verifier
  results, and adoption receipts.
- A source-minimized local catalog with policy and compatibility checks.
- Exact-byte, no-overwrite installation with rollback on failure.
- Receiver-owned adherence and obligation verification under Bubblewrap.
- Python embedding and bounded stdio MCP connector surfaces.
- Authoring and sealing commands, a one-command demo, conformance fixtures,
  and tests.

This repository is the inspectable foundation of the Limitless product. Its
trust and foundation commitments are described in
[Open-source foundation](docs/OPEN-SOURCE-FOUNDATION.md).

## Manual conformance proof

The smaller `examples/` fixture exposes each primitive separately:

```bash
limitless validate-catalog --catalog examples/catalog

limitless query \
  --catalog examples/catalog \
  --request examples/requests/exact-python.json
```

Continue through installation, method guidance, abstention, and authoring in
the [conformance example](examples/README.md).

## MCP

Start the bounded local stdio server:

```bash
limitless-mcp --catalog examples/catalog
```

It exposes `limitless_query_before_work` and supports stateless MCP
`2026-07-28` requests plus the legacy `2025-03-26` initialization flow. MCP is
a decision channel, not an artifact transport; installation remains an
explicit receiver-local operation.

Python callers can use `query_local(...)` or `McpStdioConnector`. See
[Protocol](docs/PROTOCOL.md).

## Authoring

The checked-in `examples/authoring` records omit derived digests. Seal them
only after payload and receiver-verifier review:

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

Outputs are immutable: both commands refuse to overwrite an existing path.

## Documentation

| Guide | Purpose |
| --- | --- |
| [Local demo](docs/LOCAL-DEMO.md) | Evidence map and manual inspection |
| [Protocol](docs/PROTOCOL.md) | Local API and MCP contract |
| [Trust model](docs/TRUST-MODEL.md) | Security boundaries and failure behavior |
| [Conformance](docs/CONFORMANCE.md) | Required outcomes and fixture expectations |
| [Open-source foundation](docs/OPEN-SOURCE-FOUNDATION.md) | Relationship between the open implementation and product |
| [Examples](examples/README.md) | Primitive-by-primitive walkthrough |

## Status and security

This is a pre-alpha reference implementation. It is intentionally local,
single-operator, and Linux-only for contained verification. It is not yet a
remote trust system or package manager, and technical integration is not
treated as product adoption.

There is deliberately no unsandboxed verifier fallback. Querying and method
selection work without Bubblewrap; exact adoption fails closed if containment
is unavailable. Schemas and interfaces may change incompatibly before `0.1.0`
stable.

Read the [trust model](docs/TRUST-MODEL.md) before use. Report vulnerabilities
according to [SECURITY.md](SECURITY.md).

## Contributing and license

Contributions should preserve fail-closed behavior, non-disclosure on
abstention, and receiver ownership of verification. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

Apache-2.0 licensed. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

<p align="center">
  A <a href="https://univeracity.com">Univeracity</a> project ·
  <a href="https://limitlesslibrary.com">limitlesslibrary.com</a>
</p>
