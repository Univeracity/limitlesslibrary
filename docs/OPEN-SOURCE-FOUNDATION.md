# Open-source foundation

## Commitment

The open project is the inspectable trust foundation of Limitless, not a
disposable SDK or abbreviated simulation. A local operator can perform the
complete verified-reuse lifecycle without an account or Limitless-operated
service: create and seal a capsule, make a policy- and compatibility-bound
decision, install exact bytes without overwrite, run receiver-owned checks in
containment, verify runtime invocation, and retain lifecycle evidence.

The same public schemas and behavioral invariants are intended to remain the
foundation for other Limitless product surfaces. An operator should not have to
trust an undocumented implementation of the core reuse decision.

## Included

- Content-addressed capsule, decision, recipe, verifier, and receipt formats.
- Local policy and compatibility evaluation.
- Exact components and source-free methods.
- Non-disclosing abstention.
- Receiver-controlled mappings and verifier recipes.
- No-overwrite installation and failure rollback.
- Runtime adherence and functional obligation checks.
- Local catalog, CLI, Python connector, and stdio MCP adapter.
- The managed-service request/result, discovery, root-rotation, outcome, and
  submission contracts; signed conformance corpora; and a bounded opt-in HTTPS
  client.
- A meaningful bundled lifecycle demo, conformance fixtures, and tests.

## Inspectability

The local lifecycle makes no network call, sends no telemetry, and invokes no
model. Its runtime Python dependencies are `jsonschema` and `cryptography`;
exact-adoption checks also require the host's Bubblewrap executable. Decisions and receipts bind
their inputs with canonical JSON and SHA-256 digests so an evaluator can
independently reproduce what was selected and verified.

The project ships both human-readable contracts and executable conformance
tests. Neither is sufficient by itself: the schemas define accepted shapes,
while the tests define important fail-closed behavior at filesystem, process,
policy, and protocol boundaries.

## Alpha scope

This release supports a single operator and a local catalog, plus an optional
client that verifies an explicitly configured service's public authority. It
does not implement remote publisher identity, multi-party policy, managed
execution, production key custody, or verifier completeness. Internal
experiments, private receiver data, and unreleased product research are not
part of the public distribution.

These limits are explicit so users can evaluate the software on what it
actually enforces. They are not hidden prerequisites: local selection,
installation, verification, and evidence work on their own.

## Language boundary

JSON, content digests, Ed25519 signatures, HTTPS, process argv, and MCP/JSON-RPC are the public contract.
Python is the current reference implementation, not a protocol requirement. A
Rust, Go, or other implementation can conform without embedding Python if it
preserves the schemas and fail-closed behavior.

## Evidence policy

Repository stars and downloads are distribution signals, not evidence of
successful reuse. Meaningful evaluations should record time to first verified
reuse, treatment, abstention, verifier failures, follow-on cost, and repeat use.
Any future telemetry must remain explicit and opt-in.
