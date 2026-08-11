# Open-source boundary

## Purpose

The open project makes the local trust boundary inspectable and easy to test.
An evaluator should be able to create a capsule, query it, inspect every
decision input, install exact bytes, run receiver-owned checks without network
or secrets, and verify the resulting evidence without a Limitless account or
hosted service.

## Included

- Content-addressed capsule and receipt formats.
- Local policy and compatibility evaluation.
- Exact components and source-free methods.
- Non-disclosing abstention.
- Receiver-controlled mappings and verifier recipes.
- No-overwrite installation and failure rollback.
- Runtime adherence and functional obligation checks.
- Local catalog, CLI, Python connector, and stdio MCP adapter.
- Conformance examples and tests.

## Deliberately excluded

- Hosted or federated private catalogs.
- Organization identity, SSO, RBAC, policy administration, and key custody.
- Managed isolated runners and remote execution.
- Cross-organization trust, exchange, and marketplace functions.
- Proprietary ranking, suitability, and adoption intelligence.
- Organization-wide telemetry, savings analysis, audit exports, and SLAs.
- Internal experiments, design-partner records, adjacent-repository evidence,
  application materials, and unreleased research documents.

Those exclusions are product boundaries, not hidden prerequisites. The local
alpha does not call a hosted API and does not require an LLM.

## Language boundary

JSON, content digests, process argv, and MCP/JSON-RPC are the public contract.
Python is the reference implementation, not a requirement for future services
or compatible implementations. A Rust, Go, or other implementation can
conform without embedding Python, provided it preserves the schemas and
fail-closed behavior.

## Validation policy

Repository stars and downloads are distribution signals, not evidence of
successful reuse. Meaningful evaluations should record time to first verified
reuse, treatment, abstention, verifier failures, follow-on cost, and repeat use.
Telemetry is outside this alpha and must remain explicit and opt-in if added.
