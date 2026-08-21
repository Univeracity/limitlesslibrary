# Trust model

## Trust roots

The operator chooses the local catalog and receiver workspace. Capsule
redistribution rights are declared in each capsule and remain the publisher's
responsibility. The receiver owns installation targets and verifier programs.
The local stdio MCP command is an operator-selected process, not an
authenticated remote service.

The optional official service is a separate trust boundary. A supported client
release pins an immutable locator containing the exact profile digest, HTTPS
resource, service identity, and original Ed25519 root key. One explicit user
action verifies the profile, dual-signed root rotation, current discovery,
accepted policy, result-key lifetime, and exact query/result binding before
credential-free activation state is stored. TLS protects transport; the
release-pinned root authenticates service content. Alternate profiles remain
an advanced, explicit operator surface.

Activation also creates a service-specific Ed25519 installation key and
verifies the service's signed attestation before obtaining a short-lived
anonymous session. The key remains in an owner-only local file. Public
publication additionally requires an explicit policy confirmation and a
signed intent that names exact selected objects; the client never treats
workspace discovery or connection as publication consent.

## Enforced properties

- Strict JSON rejects duplicate keys and non-finite values.
- JSON Schemas reject unknown fields at the public trust boundary.
- Capsule, decision, recipe, file, result, receiver-state, and receipt digests
  bind the exact material evaluated.
- Catalog policy checks use, tenant scope, lifecycle state, receiver
  constraints, and declared toolchain compatibility before selection.
- Equal-priority ambiguity and ineligibility produce the same non-disclosing
  abstention shape.
- Exact installation preflights all source and target paths, rejects symlinks,
  refuses overwrite, and removes files created by a failed attempt.
- Receiver verifiers are digest-bound and run with no network, no inherited
  secrets, a read-only receiver, bounded time/memory/files/output, and a
  minimal runtime mount.
- Exact installed files are rehashed after verification.
- Evidence writes are atomic and refuse overwrite.

## Claims the alpha does not make

A SHA-256 digest provides integrity, not publisher identity. Apache-2.0 text in
a capsule is a declaration, not automated legal proof. Receiver-owned checks
show what those checks establish; they do not prove the verifier is complete.
An operator authorization flag is an explicit assertion, not an identity
system. A technical adoption receipt does not mean a human owner accepted a
production dependency or would pay for the service.

The local catalog has no publisher signature, revocation distribution,
multi-tenant isolation, or supply-chain transparency log. The optional client
validates remote endpoint/result authority and publisher-facing
submission/admission records, but it does not itself implement the service's
identity, revocation, tenancy, admission, or storage systems. Do not treat a
local capsule declaration or a merely reachable endpoint as a security
boundary between mutually distrusting parties.

## Failure behavior

Missing containment, changed bytes, stale decisions, changed verifier files,
unsafe paths, ambiguity, policy mismatch, incompatible toolchains, malformed
results, and failed receiver checks stop the lifecycle. There is no host-run
fallback and no partial-success receipt.

For an opted-in service, redirects, root-chain gaps, expired discovery,
unknown result keys, policy drift, query rebinding, incompatible selections,
malformed responses, changed publication files, unsigned plans, excessive or
misbound upload requests, and stale publication policy also fail closed.
Availability and rate-limit failures return control to local reuse without
fabricating a selection.
