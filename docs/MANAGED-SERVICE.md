# Opt-in managed-service connector

Limitless Library remains complete for local selection, installation,
verification, and evidence without an account or network connection. The
optional connector adds high-signal service discovery without turning the open
client into the service or uploading a local catalog.

## One-action official activation

A supported client release may contain one `official-service-locator.json`.
The locator is not an endpoint hint: it binds the exact credential-free profile
digest and HTTPS resource to the service identity and original Ed25519 root
key. The ordinary setup is one explicit action:

```bash
limitless service-activate
```

Activation fetches the bounded profile, refuses redirects, proxies,
compression, query strings, duplicate JSON keys, unknown fields, and
over-limit responses, then verifies:

- the profile's exact canonical digest, service identity, and original root;
- an unbroken, dual-signed root-transition chain;
- current signed discovery and result-key lifetimes;
- the exact API endpoint and accepted policy digest; and
- the advertised transition-chain tip and protocol compatibility.

The same action generates one service-specific Ed25519 installation key,
self-proves its public registration, verifies the service-signed attestation,
and opens a short-lived anonymous session with the baseline query, delivery,
circle, and submission capabilities. The client does not make the user choose
those protocol scopes.

Only after every check passes does the client atomically store credential-free
activation state under the user's configuration directory. The private key
and current bearer live in a separate owner-only file, never in the activation
record or public output. Repeating the action is idempotent, rechecks service
authority, and reuses a live session; an expired session renews through one
signed POST. An authority change requires a separate, explicit replacement
decision. Availability failure leaves the local-only default unchanged.

This source release intentionally ships without a live locator. Until an owner
publishes one through a supported release, `service-activate` reports that the
service is not configured and local use continues. The repository never
invents an official identity or silently discovers an endpoint.

## Inspect and query

After activation, inspection sends no task:

```bash
limitless service-status
limitless service-inspect
```

An agent or integration can submit a complete bounded service-query record:

```bash
limitless service-query --request ./service-query.json
```

Or let the client bind the query envelope around an explicit objective and
receiver context:

```bash
limitless service-query \
  --request-id request:example-001 \
  --objective "Add a reviewed clipboard history extension" \
  --receiver ./receiver-context.json
```

Baseline public access requires no user credential: the client automatically
uses its pseudonymous installation session. A caller may still supply an
explicit advanced bearer through `LIMITLESS_SERVICE_TOKEN`; bearer material is
excluded from profiles, activation state, public output, object
representations, URLs, and query bodies.

The connector accepts only audiences and history behavior already present in
the activated profile. It verifies that the signed result binds the exact
query, receiver compatibility, current service signing key, policy digest, and
requested treatment. A timeout or availability response returns a distinct
error so the caller can continue with local reuse or fresh work; it never
fabricates a remote selection or silently weakens the accepted boundary.

## Advanced alternate profiles

Operators building another compatible service can bypass the official
activation state only through the explicit lower-level option:

```bash
limitless service-inspect --profile ./owner-reviewed-profile.json
limitless service-query \
  --profile ./owner-reviewed-profile.json \
  --request ./service-query.json
```

Current profiles use `limitless.service-profile/1.1` and separately declare
`executionMode`, `defaultAudience` (`private`, `circle`, `organization`, or
`public`), `historyMode` (`local-only` or `service-persisted`), and
`requestedAudiences`. Legacy 1.0 profiles remain a validation and transport
compatibility seam; new public output does not use their older policy
vocabulary.

Python callers use `ServiceProfile`, `ServiceConnector`, and the functions in
`limitless_library.official_service`. Packaged conformance corpora freeze the
signed query lifecycle, installation registration/session records, and
root-rotation behavior for other language implementations.

## Deliberate exclusions

Connecting does not publish work, enumerate a workspace, upload a local
catalog, install a returned component, hand off to a native provider, or submit
local outcome evidence. Those are separate owner-authorized continuations. The
service-side identity authority, managed implementation, ranking, persistence,
analytics, and deployment remain outside this repository.
