# Conformance profile

A compatible `0.1` local implementation must pass the behavioral cases covered
by `tests/`:

- strict JSON and safe relative paths;
- schema-valid, reproducible capsule and recipe sealing;
- deterministic exact, method, and non-disclosing abstention decisions;
- abstention on equal-priority ambiguity, revocation, policy mismatch, and
  incompatibility;
- rejection of changed exact bytes, changed verifier bytes, stale or altered
  decisions, unsafe targets, and overwrite attempts;
- exact installed byte equality and rollback after failed verification;
- receiver-runtime invocation plus receiver-owned functional obligations;
- immutable, content-bound adoption evidence;
- MCP 2026 discovery, tool metadata, structured decisions, request binding,
  protocol rejection, response size limits, and deadlines.

Passing this profile proves behavior of the tested implementation and host. It
does not establish publisher identity, legal rights, verifier completeness, or
production adoption.
