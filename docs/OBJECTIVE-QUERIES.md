# Check reusable work with one objective

`limitless_check` accepts only `{"objective": "what you intend to do"}`. The
CLI equivalent is `limitless check --objective "what you intend to do"`.
Neither input accepts credentials, a receiver path, policy overrides, or a
service endpoint. The owner configures those boundaries separately.

The client checks its configured local catalog and private captured methods
first. If a useful local result fits, it skips the service. If none fits and
the owner permits service queries, the existing connector authenticates the
service and verifies its signed result. The response contains one treatment:
method guidance, a component to verify before adoption, or honest abstention.
Querying never fetches artifact bytes, installs files, or executes a verifier.

## Defaults and service consent

No seed catalog is required. `limitless-mcp` can capture methods and check them
through one connection. An explicitly provided `--catalog` retains the original
catalog loading and integrity checks.

The default query policy uses this device's observed platform for local method
eligibility. It does not infer the language or toolchain of a receiving program.
The default service context requests source-free methods with `derive-method`
use, and describes unknown target runtimes as unknown rather than borrowing the
agent host's Python version. Exact selection is disabled until the owner provides
receiver facts and elects it.

Activating the service does not itself permit objective-based MCP queries.
After reviewing service activation, use:

```sh
limitless query-policy --execution-mode service
```

Inspect with `limitless query-policy`; disable with
`limitless query-policy --execution-mode local`. This policy is stored separately
from service activation, publication consent, and existing plugin settings. It
is reloaded on each query and checked again before transferring an objective.
Public contribution still requires its own standing authorization and reviewed
publication-policy digest.

## Configure the actual receiver

When work targets another device or program, configure that receiver rather
than treating the agent host as the target. Advanced setup accepts an existing
service receiver context and/or a local receiver's constraints and toolchain:

```sh
limitless query-policy \
  --service-receiver /absolute/path/to/service-receiver.json \
  --local-receiver /absolute/path/to/local-receiver.json \
  --allow-exact
```

Local exact selection requires the local receiver facts. Service exact selection
uses the declared service targets and allowed use. Host-owned receiver facts are
declarations to check, not proof of compatibility or successful adoption. The
existing role-separated receiver environment can produce the bounded service
context; see [the receiver example](../examples/receiver-context.json).

Use `--requested-use` and `--tenant-scope` for an existing local catalog with
different declared policy labels. These affect local eligibility; they do not
grant remote audience authority. `--method-only` disables exact selection again.

## Results and continuity

`limitless.objective-result/1.0` carries one selection, its content digest, a next
action, and separate local/service/continuation coverage. Its integrity labels
distinguish local catalog digests from a verified service signature. Every result
keeps `outcome: not-asserted`; successful delivery is not evidence of receiver use.

Generic action words in verification text do not establish topic fit. Objective
selection considers descriptive title and summary matches across task kinds and
requires a unique best eligible result. The original structured query's selection
rules and `limitless.decision/0.1` wire shape remain unchanged.

Replies are limited to 32 KiB. A method is never silently truncated to meet this
limit; an oversized result becomes an explicit abstention. Incomplete local
coverage or unavailable service search is visible rather than represented as a
complete unsuccessful search.

A `queryRef` addresses an immutable private continuation record containing the
underlying query and validated decision. Signed service results remain intact
there, including any short-lived delivery authority. Those credentials, artifact
URLs, local paths, raw source, and verifier output are excluded from MCP replies.
The view's own digest is not a substitute for the underlying service signature.
Later operations must revalidate that underlying authority and receiver state.

Records use the sibling `queries` directory beside the method store, with private
directory/file permissions. Each record is capped at 256 KiB and the store at
2,000 records. Current continuation writing requires POSIX. If storage is unsafe,
busy, full, or unavailable, querying still returns useful guidance and reports
`continuation: unavailable` with a null `queryRef`; it does not invent a usable
continuation. Records stay local and are not automatically published.

Advanced hosts may bind `--query-policy` and `--query-state` at MCP startup or on
the CLI. Neither path becomes a model tool argument. Original Python connectors
receive their compatible query-only listing; other agents discover the new tool
alongside the existing tools.
