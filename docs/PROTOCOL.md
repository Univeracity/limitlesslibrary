# Protocol alpha

The canonical schemas are packaged in `limitless_library.schemas`:

| Record | Schema | Purpose |
| --- | --- | --- |
| Capsule | `capsule-0.1.schema.json` | Public offers, policy, compatibility, exact files, and methods |
| Query | `query-0.1.schema.json` | Receiver need and evaluation context |
| Decision | `decision-0.1.schema.json` | Exact reuse, method instantiation, or abstention |
| Recipe | `recipe-0.1.schema.json` | Receiver-owned mappings and digest-bound verifiers |
| Verifier result | `verifier-result-0.1.schema.json` | Adherence or functional result |
| Adoption receipt | `adoption-receipt-0.1.schema.json` | Bound technical lifecycle evidence |

Logical record digests use UTF-8 JSON with sorted object keys, no insignificant
whitespace, no ASCII escaping requirement, and no NaN or Infinity. The digest
string is `sha256:` followed by 64 lowercase hexadecimal characters. A record's
own digest field is omitted while calculating that digest.

## Selection

An offer is eligible only when all of the following hold:

1. Task kind matches exactly.
2. Lifecycle state is `active`.
3. Requested use and tenant scope are listed or wildcarded.
4. Every offer constraint is present in the receiver constraints.
5. Every required toolchain value is in the offer's allowed value list.

The unique highest-priority eligible offer wins. When the optional local
`objective` is present, a unique positive lexical match may break a tie among
only the highest-priority eligible offers; an absent, unmatched, or still-tied
objective abstains. Objective relevance never overrides rights, compatibility,
scope, state, or explicit priority. Exact offers produce `reuse`/`exact-adoption`; method offers produce
`instantiate`/`method-guided`. Abstention contains no candidate details.

## MCP

The stdio server accepts one JSON-RPC object per line, capped at 1 MiB. Modern
requests carry `io.modelcontextprotocol/protocolVersion=2026-07-28`, client
capabilities, and optional client information in `params._meta`. The server
implements `server/discover`, `tools/list`, and `tools/call` independently.

The `2025-06-18` and legacy `2025-03-26` modes require a successful
`initialize` followed by `notifications/initialized` before tool requests, and
the server echoes the admitted revision. Client or server identity metadata is
diagnostic and never an authorization input.

The MCP tool returns the decision as `structuredContent` and as canonical JSON
text for clients that consume text content. Artifact bytes never cross MCP.

## Managed-service façade

The optional service connector uses the versioned public records implemented
in `limitless_library.service_contracts`:

- current query `limitless.service-query/1.1`, with validation-only `1.0`
  compatibility;
- current result `limitless.service-query-result/1.4`; discovery advertises
  `1.1`–`1.4`, while `1.0` remains validation-only for historical evidence;
- current discovery `limitless.service-discovery/1.2`, with `1.0` and `1.1`
  compatibility;
- `limitless.service-root-key-transition/1.0` and its bounded set;
- `limitless.service-profile/1.1`, official-service locator `1.0`, and local
  activation state `1.0`;
- installation registration, service attestation, session request, and session
  response `1.0` records;
- outcome attempt/receipt `1.0`;
- current signed submission intent `1.2`, plan `1.0`, content-transfer
  grant/result `1.0`, and immutable release `1.2`, with `1.0`/`1.1`
  validation compatibility; and
- contribution-policy acceptance, admission assessment/status, and release
  revocation `1.0` records.

The packaged `limitless_library.conformance` corpora contain signed positive
vectors and declared negative mutations for the query lifecycle, anonymous
installation identity, and root-key rotation. These records are the public
compatibility surface; private ranking, identity persistence, policy
evaluation, service storage, and deployment records are not.

Current result `1.4` exact-artifact selections carry a query-free HTTPS URI,
one-use `Limitless-Capability` header value, exact positive byte length, and
the closed `limitless.exact-file-bundle/1.0` format/media-type pair inside the
signed selection. Artifact bytes do not cross MCP or the JSON query response.
The continuation streams at most 64 MiB into an unpublished owner-only
temporary file, verifies the signed/declared/received length and digest, and
publishes without overwrite. Receiver installation remains separate. A client
must not infer this descriptor for older results; historical `1.3` artifacts
remain opaque and use their legacy bounded staging path.

Signed submission intent `1.2` establishes where that descriptor
must originate. Its artifact content object binds the same closed bundle
format, vendor media type, digest, and positive length of at most 64 MiB; the
immutable release `1.2` preserves the descriptor byte for byte. Non-artifact
objects retain their three-field shape, and missing-content plans intentionally
carry only role, digest, and length so the existing transfer grant/result
protocol does not acquire interpretation authority. The packaged static corpus
proves intent, plan, and release signatures plus declared format, media-type,
size, and signature mutations across implementations.

This generation is active across ordinary publication, admission, projection,
delivery authorization, and result `1.4`. Before signing an artifact
publication, the client parses its bytes as a canonical exact file bundle and
binds the known format and media type into the intent. Existing `1.0`/`1.1`
releases remain format-blind and must never be upgraded by sniffing or private
source hints.

Public contribution uses a separate query-free data plane. Signed discovery
advertises its upload version and maximum object size. The client negotiates a
digest-first signed plan, then sends each missing object with `PUT` to the
submission-, role-, and digest-bound path. Length, digest, media type,
publisher session, current policy acceptance, and admission state must all
agree before immutable publication. A transfer result is non-authoritative;
the client retries negotiation to establish that the object catalog now sees
the exact bytes.

See [Managed-service connector](MANAGED-SERVICE.md) for one-action official
activation, advanced profiles, and the HTTPS boundary.
