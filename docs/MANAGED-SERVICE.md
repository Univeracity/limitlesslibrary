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

Supported releases ship a content-addressed official locator for
`api.limitlesslibrary.com`. Source trees and compatible third-party builds may
omit it; in that case `service-activate` reports that the service is not
configured and local use continues. The client never invents an official
identity or silently discovers an endpoint.

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

## Exact artifact continuation

A current exact-component result can select one bounded artifact without
placing authority in a URL. The ordinary CLI can consume that result in the
same invocation:

```bash
limitless service-query \
  --request ./service-query.json \
  --artifact-output ./selected.bin
```

The client revalidates the signed result against the exact query and current
service keys. Result `1.5` then selects one signed delivery lane: immutable
public-edge objects need no credential, while protected objects use the
anonymous session bearer and one-use `Limitless-Capability` header. Both lanes
refuse redirects, query strings, and compression; stream at most 64 MiB; and
require the response media type, length, and digest to agree with the signed
selection. The client then creates an owner-only file atomically and refuses to
overwrite an existing path. The printed staging summary contains neither a
bearer nor delivery capability.

Staging only preserves the verified handoff. A receiver or native provider
must still interpret the signed `nextAction`, install under its own rules,
verify locally, observe use, and decide whether to submit outcome evidence. A
failed integrity check never publishes bytes to the destination.

A receiver adapter that must continue after the query process exits without
retaining objective text may keep the already verified signed result and its
request digest in receiver-owned protected state, then call
`fetch_selected_artifact_continuation(...)`. That continuation accepts only the
current result contract, re-verifies the service signature and lifetime, binds
the exact request digest and opted-in policy/audiences, and still stages with
no overwrite. The generic Library does not create that local state or infer a
receiver installation from it; custody and native handling belong to the
explicit receiver adapter.

The first open payload shape for a native continuation is
`limitless.exact-file-bundle/1.0`, exposed through
`build_exact_file_bundle(...)` and `parse_exact_file_bundle(...)`. It is a
canonical, digest-bound directory tree with no hooks or install target. Merely
parsing it does not authorize extraction or installation: a locally installed
receiver adapter must still match the signed result's compatibility interface
and apply receiver-owned review, validation, and no-overwrite rules. Existing
service result 1.3 artifacts remain format-blind and therefore stop at opaque
staging.

The current `limitless.service-query-result/1.5` contract binds that format,
its vendor media type, a positive byte length, and its public-edge or
protected-capability delivery mode into the signed artifact descriptor. It is
advertised by discovery and requested by default. The connector streams no
more than 64 MiB into a mode-0600 temporary file, hashes and counts bounded
chunks, requires the response headers and signed descriptor to agree, and
publishes by no-replace hard link only after verification. Interrupted or
mismatched streams leave no destination. Parsing and receiver-native
installation remain separate explicit adapter responsibilities.

## Explicit anonymous publication

The same service-specific installation key can sign a public contribution
without account creation, pasted credentials, or a second agent reasoning
turn. The user supplies a narrow draft and explicitly confirms the exact
publication policy advertised by signed discovery:

```bash
limitless service-publish \
  --draft ./examples/publication/publication.draft.json \
  --accept-publication-policy-digest "$REVIEWED_PUBLICATION_POLICY_DIGEST"
```

Set `REVIEWED_PUBLICATION_POLICY_DIGEST` to the exact
`publicationPolicy.digest` returned by `service-inspect` after reviewing its
policy URL. The submission fails closed if signed discovery has since changed
that digest.

The draft names only selected objects. Relative paths resolve from the draft's
directory, never an assumed current working directory. On the first run the
client first requires the exact reviewed digest to match the currently signed
publication policy. It then hashes those regular files, binds their descriptors
and the current anonymous publisher authority into a signed intent, and creates
an immutable mode-0600 state file beside the draft. A retry reuses that intent
and request identity, so an interrupted transfer cannot silently become another
release.

The client sends the signed policy acceptance and intent as bounded JSON,
receives a signed plan and short-lived content authorization, and streams only
objects the plan says are missing.
Each upload uses a query-free path, `application/octet-stream`, exact length
and digest headers, and the short-lived anonymous bearer. It rehashes the open
file while sending; the service reauthorizes the current admission state,
hashes and counts the stream into an uncommitted object, and publishes only an
exact put-if-absent result. It reports active, pending, quarantined, or rejected
admission as a publication result rather than conflating review state with a
network failure. Source paths,
private keys, bearers, and workspace contents outside the draft never enter
the submission records.

The current signed intent/release `1.2` contract defines the format-aware
publication boundary. An artifact object
must name the exact `limitless.exact-file-bundle/1.0` format, its vendor media
type, digest, and bounded positive byte length; the immutable release preserves
all of those fields. Missing-content plans still project only role, digest, and
length, keeping upload authority separate from interpretation authority. The
ordinary CLI first parses an artifact source as a canonical exact bundle, then
binds that descriptor into intent `1.2`; signed discovery advertises the
generation. Older releases stay opaque rather than being retroactively
classified from their bytes or provenance.

The bundled example is directly publishable from a supported release after the
publisher reviews and accepts the currently advertised policy digest. The open
client validates the public wire lifecycle but does not
contain the private admission engine, ranking service, or managed storage.

The returned owner-only state is also the durable handle for follow-up:

```bash
limitless service-publication-status --state ./publication.draft.json.state.json
limitless service-publication-revoke --state ./publication.draft.json.state.json
```

Status derives the submission identity from the signed publisher request; it
does not resend content. Revocation first resolves the publisher-visible active
release, then signs a short-lived withdrawal with the current installation key.
An already revoked release returns its existing state without creating another
withdrawal request. Pending, quarantined, rejected, or retired work cannot be
misrepresented as an active release eligible for withdrawal.

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
signed query lifecycle, installation registration/session records, public
submission/admission records, and root-rotation behavior for other language
implementations.

## Deliberate exclusions

Connecting does not publish work. Only `service-publish` transfers the exact
objects named in its reviewed draft; it does not enumerate a workspace or
upload a local catalog. The client also does not install a staged component,
hand off to a native provider, or submit local outcome evidence. Those remain
separate owner-authorized continuations. The service-side identity authority,
managed admission implementation, ranking, persistence, analytics, and
deployment remain outside this repository.
