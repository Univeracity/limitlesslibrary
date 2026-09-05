<p align="center">
  <img src="docs/assets/limitless-library-mark.png" width="148" alt="Limitless Library mark">
</p>

<h1 align="center">Limitless Library</h1>

<p align="center">
  <strong>AI agents default to building from scratch, wasting time and tokens.<br>
  Limitless helps them find, verify, and reuse previous work.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-111111"></a>
  <a href="https://github.com/Univeracity/limitlesslibrary/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/Univeracity/limitlesslibrary/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.11 or newer" src="https://img.shields.io/badge/python-3.11%2B-111111">
  <a href="docs/PROTOCOL.md"><img alt="MCP 2026-07-28" src="https://img.shields.io/badge/MCP-2026--07--28-111111"></a>
  <img alt="Preview" src="https://img.shields.io/badge/status-preview-6b7280">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-verified-reuse-works">Lifecycle</a> ·
  <a href="#mcp">MCP</a> ·
  <a href="#connect-an-agent">Connect an agent</a> ·
  <a href="#connect-to-limitless-library-service">Service</a> ·
  <a href="#use-it-with-omarchy">Omarchy</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Stop rebuilding work that already exists

Without Limitless, an agent gets a task and starts from zero—even when another
agent has already completed useful work. With Limitless, it checks first. One
quick query can return a reusable component, a practical method, or an honest
instruction to start fresh.

> **Without Limitless:** task → rebuild from scratch<br>
> **With Limitless:** task → check first → reuse what fits or start fresh

Finding prior work is only half the problem. Limitless also checks whether it
is allowed, compatible, unchanged, and actually adopted. The receiving
environment keeps control: it decides what may enter and verifies exact reuse
locally.

![Verified reuse lifecycle: query before work; evaluate rights and fit; return an exact component, a source-free method, or a non-disclosing abstention; verify exact reuse locally; observe invocation; and return an adoption receipt.](docs/assets/verified-reuse-flow.svg)

## At a glance

| Property | What it means |
| --- | --- |
| **Three safe outcomes** | Exact component, source-free method, or abstention |
| **Receiver-owned proof** | The receiving environment chooses installation paths and verification programs |
| **Exact bytes** | Content-addressed installation refuses overwrite and rolls back on failure |
| **Fail-closed verification** | No network, inherited secrets, or unsandboxed verifier fallback |
| **Observed use** | Delivery is not counted as reuse until receiver code invokes the supplied component |
| **Real receiver facts** | The agent host, work location, operating target, and place where success is observed can remain distinct |
| **Local by default** | The reference lifecycle needs no account, hosted service, or model API |
| **Inspectable service trust** | The optional connector pins service authority, policy, protocol, and signed results |

## Try it now

| Starting point | Best for | What you get |
| --- | --- | --- |
| [Local quick start](#quick-start) | Inspecting the complete lifecycle | Exact adoption, method guidance, and abstention with no account or hosted service |
| [Public service](#connect-to-limitless-library-service) | Searching and contributing to the shared Library | Anonymous activation, high-signal discovery, signed results, and reviewed public intake |
| [Verified Omarchy plugin](https://omarchyplugins.com/plugin.html?id=univeracity.limitless-library) | Omarchy users who want a native interface | A panel, bar widget, local catalog, agent connection, and optional service access |

## Quick start

Try the complete local lifecycle from a source checkout. You need Python 3.11
or newer and [Bubblewrap](https://github.com/containers/bubblewrap) on Linux.
On Debian or Ubuntu, install the one system dependency if it is not already
present:

```bash
sudo apt-get install bubblewrap
```

Then run:

```bash
git clone https://github.com/Univeracity/limitlesslibrary.git
cd limitlesslibrary
./scripts/limitless
```

That is the only project command required. On first use, the launcher creates
an isolated environment under `.limitless/`, installs the small Python
dependency set, runs exact adoption, method guidance, and safe abstention, and
retains inspectable evidence under `.limitless/quickstart`. It requires no
environment activation, account, cloud service, model API, or model download.
The initial dependency installation may require package-index access; the
lifecycle itself runs without network access.

Check host readiness or retain another run at a path you choose:

```bash
./scripts/limitless doctor
./scripts/limitless demo --workspace ./limitless-demo
```

The demo refuses to overwrite an existing workspace. Later launcher runs reuse
the isolated environment; running it without arguments keeps the original
quick-start evidence and performs a disposable replay.

When integrating Limitless into another environment, install the checkout with
`python -m pip install .`; the installed commands are `limitless` and
`limitless-mcp`.

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

The agent's current machine is not automatically the receiver. A local
receiver-environment profile can separately bind the agent host, the place
being changed, one or more operating targets, and the environments or people
capable of observing success. This covers cases such as a Linux-hosted agent
building for Windows or an agent repairing a remote physical device. Only the
host execution and target compatibility facts needed for service matching are
projected across the network; work locations, hardware attributes, fact
provenance, and physical-observation details stay local.

If exact bytes do not fit, only a source-free method may cross. If no safe
candidate exists, Limitless abstains without disclosing one.

## What is open here

- JSON Schemas for capsules, queries, decisions, receiver recipes, verifier
  results, adoption receipts, role-separated environments, and composite
  receiver evidence.
- A source-minimized local catalog with policy and compatibility checks.
- Exact-byte, no-overwrite installation with rollback on failure.
- Receiver-owned adherence and obligation verification under Bubblewrap.
- Python embedding and bounded stdio MCP connector surfaces.
- Versioned managed-service wire contracts, signed conformance corpora, and an
  explicitly activated, release-pinned HTTPS connector with anonymous
  installation identity, short-lived sessions, exact artifact staging, and
  resumable public contribution.
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
`2026-07-28` requests plus the `2025-06-18` and legacy `2025-03-26`
initialization flows. Initialization-era clients complete `initialize` and
`notifications/initialized` before requesting a tool. MCP is a decision
channel, not an artifact transport; installation remains an explicit
receiver-local operation.

Python callers can use `query_local(...)` or `McpStdioConnector`. See
[Protocol](docs/PROTOCOL.md).

## Connect an agent

This repository currently includes a direct setup adapter for Antigravity CLI
(`agy`). Other hosts can connect through the documented stdio MCP surface;
Omarchy users get verified setup adapters for Codex, Claude Code, Grok, and
Antigravity through the plugin described below.

Connect Antigravity to an explicit local catalog with one command:

```bash
limitless agent-connect antigravity --catalog /absolute/path/to/catalog
```

The command adds one named `limitless-library` stdio server to Antigravity's
documented MCP profile. It uses the exact Python environment that ran
`limitless`, so there is no separate executable to find or PATH assumption to
maintain. Restart Antigravity CLI, then its MCP instructions and the
`limitless_query_before_work` tool are available before material work.

```bash
limitless agent-status antigravity
limitless agent-disconnect antigravity
```

The integration preserves all unrelated MCP entries. It keeps a small local
ownership record containing only the profile path and its own command/args,
and disconnect removes an entry only if those exact values still match. A
pre-migration Antigravity installation uses its existing legacy profile; a
migrated or new installation uses Antigravity's current global profile. This
local connection neither activates the managed service nor sends a query until
the agent calls the tool.

## Use it with Omarchy

The [verified Limitless Library plugin](https://omarchyplugins.com/plugin.html?id=univeracity.limitless-library)
is live in the Omarchy marketplace. Install it from Omarchy's plugin interface,
or use the marketplace command:

```bash
omarchy plugin add https://github.com/Univeracity/limitless-omarchy.git --enable
```

The plugin provides a native panel and bar widget, installs its private local
runtime from the UI, connects the owner's selected agent where supported, and
keeps service discovery opt-in. It supports both Omarchy customization and
general agent work, so users do not need a second Limitless package.

See the [Omarchy product page](https://limitlesslibrary.com/omarchy) or inspect
the [plugin source](https://github.com/Univeracity/limitless-omarchy).

## Connect to Limitless Library service

Local use remains available without the service. The official client bundles
one content-addressed service locator. A single explicit action fetches the
exact credential-free profile, verifies its pinned identity, Ed25519 root and
rotation chain, accepted policy, and discovery document, then stores that trust
boundary locally. It also creates one service-specific signing key, verifies
the service's installation attestation, and obtains a short-lived anonymous
session. No account, downloaded profile, pasted token, or API key is required
for baseline public access. The examples below use an installed `limitless`
command; from a source checkout, use `./scripts/limitless` instead.

```bash
limitless service-activate
limitless service-inspect
limitless service-query --request ./service-query.json

# When the verified result selects an exact artifact:
limitless service-query \
  --request ./service-query.json \
  --artifact-output ./selected.bin
```

The service accepts anonymous activation, queries, outcome evidence, and
public contributions. A contribution can contain an independently authored
source-free method or a canonical exact file bundle that keeps its declared
source license and notices. Both enter protected staging before admission;
only admitted releases become globally queryable. Advanced integrations may
still pass an owner-reviewed alternate profile with `--profile`. The client
validates root rotation, signed discovery, policy continuity, query binding,
compatibility, and the signed result before returning it. Remote failure yields
control back to local reuse. Connecting
alone never publishes a local capsule or silently installs selected work.
Exact remote artifacts move only after the caller supplies
`--artifact-output`: public immutable objects need no credential, while
protected objects use a signed capability header. Both lanes verify the
declared format, media type, length, and digest and create a new owner-only file
without overwrite.
Staging is not parsing, installation, or proof of adoption; those remain
receiver-adapter responsibilities.

Publication is explicit but account-free. After inspecting the service and
reviewing its advertised publication policy, publish the bundled source-free
method example with the exact policy digest shown by `service-inspect`:

```bash
limitless service-publish \
  --draft ./examples/publication/publication.draft.json \
  --accept-publication-policy-digest 'sha256:<reviewed-policy-digest>'
```

`service-publish` accepts only the files named by the draft, resolves them
relative to that draft rather than the current directory, and prepares a
signed, resumable owner-only state file before transfer. It negotiates digests
first, streams only missing bytes, and returns the admission state. That state
supports later status inspection and explicit withdrawal without storing a
credential in the draft or command line. A quarantined or rejected
contribution is reported honestly rather than mistaken for a network failure.
The client does not scan or upload a workspace. Artifact sources must already
be canonical
`limitless.exact-file-bundle/1.0` payloads; the client verifies that shape
locally and binds it into the current signed publication intent. See the
[managed-service connector](docs/MANAGED-SERVICE.md).

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
| [Managed-service connector](docs/MANAGED-SERVICE.md) | Explicit endpoint, trust, policy, and query boundary |
| [Trust model](docs/TRUST-MODEL.md) | Security boundaries and failure behavior |
| [Conformance](docs/CONFORMANCE.md) | Required outcomes and fixture expectations |
| [Open-source foundation](docs/OPEN-SOURCE-FOUNDATION.md) | Relationship between the open implementation and product |
| [Examples](examples/README.md) | Primitive-by-primitive walkthrough |

## Status and security

This repository is an alpha package and the open-source foundation of a live
preview. The complete local lifecycle works without an account or hosted
service and remains single-operator. Contained exact verification currently
requires Linux and Bubblewrap; querying and method selection do not.

The official public service is usable now for anonymous activation, discovery,
signed decisions and results, exact-artifact staging, outcome evidence, and
reviewed public contribution. The private admission, ranking, managed-storage,
and multi-tenant service implementation is intentionally outside this
repository; its public wire contracts, connector, conformance fixtures, and
trust checks are open here. Account-backed history and private group or
organization coordination remain under development.

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
  <a href="https://limitlesslibrary.com">limitlesslibrary.com</a> ·
  <a href="https://omarchyplugins.com/plugin.html?id=univeracity.limitless-library">Omarchy plugin</a>
</p>
