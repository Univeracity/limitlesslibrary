# Opt-in managed-service connector

Limitless Library remains complete for local selection, installation,
verification, and evidence without an account or network connection. The
optional connector adds high-signal remote discovery without turning the open
client into the managed service or uploading a local catalog.

## Explicit profile

The connector does not discover or select an endpoint implicitly. An operator
must provide a profile containing the exact HTTPS endpoint, service identity,
pinned Ed25519 root key, accepted data-use policy digest, data-use mode, and
allowed scopes:

```json
{
  "schemaVersion": "limitless.service-profile/1.0",
  "apiBaseUrl": "https://api.example.com",
  "serviceId": "service:example",
  "rootKey": {
    "keyId": "root:example",
    "algorithm": "ed25519",
    "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },
  "acceptedPolicyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "dataUseMode": "confidential",
  "requestedScopes": ["public"]
}
```

The values above are placeholders, not a live service profile. Obtain the
complete profile through an authenticated or otherwise trusted publication
channel. A changed endpoint, service identity, trust root, policy digest, or
scope requires another explicit operator decision.

If a service profile requires authentication, supply its bearer credential only
through `LIMITLESS_SERVICE_TOKEN`. The token is excluded from profile files,
public status output, object representations, query bodies, and persisted
trust material.

## Verify the service boundary

```bash
limitless service-inspect --profile ./service-profile.json
```

This command fetches the bounded root-transition set and discovery document,
then verifies:

- an unbroken, dual-signed transition chain from the pinned root;
- the current discovery signature and signing-key lifetime;
- the exact service identity and API endpoint;
- supported protocol and result versions;
- the accepted data-use policy digest; and
- the advertised transition-chain tip.

Redirects, ambient HTTP proxies, compressed responses, duplicate JSON keys,
unknown fields, expired documents, key substitutions, and policy drift fail
closed.

## Query

An agent or integration can submit a complete
`limitless.service-query/1.0` record:

```bash
limitless service-query \
  --profile ./service-profile.json \
  --request ./service-query.json
```

Or let the client bind the query envelope around an explicit objective and
receiver context:

```bash
limitless service-query \
  --profile ./service-profile.json \
  --request-id request:example-001 \
  --objective "Add a reviewed clipboard history extension" \
  --receiver ./receiver-context.json
```

The connector accepts only scopes and the data-use mode already present in
the profile. It verifies that the signed result binds the exact query,
receiver compatibility, current service signing key, policy digest, and
requested treatment. A remote timeout or availability response returns a
distinct `ServiceUnavailableError` so the caller can continue with local reuse
or fresh work; it never fabricates a remote selection or silently weakens the
data-use mode.

Python callers use `ServiceProfile`, `ServiceConnector.build_query(...)`, and
`ServiceConnector.query(...)`. The packaged
`limitless_library.conformance` corpora freeze the signed query lifecycle and
root-rotation behavior for other language implementations.

## Deliberate exclusions

Connecting does not publish work, enumerate a workspace, upload a local
catalog, install a returned component, hand off to a native provider, or submit
local outcome evidence. Those are separate owner-authorized continuations.
The managed implementation, identity system, ranking, persistence, analytics,
and deployment remain outside this repository.
