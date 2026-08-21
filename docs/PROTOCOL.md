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

The unique highest-priority eligible offer wins. A tie abstains. Exact offers
produce `reuse`/`exact-adoption`; method offers produce
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
- current result `limitless.service-query-result/1.3`, with validation-only
  `1.0`–`1.2` compatibility; explicit experimental `1.4` construction and
  validation is available for conformance but is not advertised by discovery;
- current discovery `limitless.service-discovery/1.2`, with `1.0` and `1.1`
  compatibility;
- `limitless.service-root-key-transition/1.0` and its bounded set;
- `limitless.service-profile/1.1`, official-service locator `1.0`, and local
  activation state `1.0`;
- installation registration, service attestation, session request, and session
  response `1.0` records;
- outcome attempt/receipt `1.0`;
- signed submission intent `1.1`, plan `1.0`, content-transfer grant/result
  `1.0`, and immutable release `1.1`; and
- contribution-policy acceptance, admission assessment/status, and release
  revocation `1.0` records.

The packaged `limitless_library.conformance` corpora contain signed positive
vectors and declared negative mutations for the query lifecycle, anonymous
installation identity, and root-key rotation. These records are the public
compatibility surface; private ranking, identity persistence, policy
evaluation, service storage, and deployment records are not.

Current exact-artifact selections carry a query-free HTTPS URI and one-use
`Limitless-Capability` header value inside the signed result. Artifact bytes do
not cross MCP or the JSON query response. The opt-in HTTPS continuation accepts
at most 128 KiB of `application/octet-stream`, binds its length and digest to
the signed selection, and stages it without overwrite. Receiver installation,
verification, observed invocation, and outcome submission remain distinct
events.

Experimental result `1.4` additionally binds an exact positive byte length and
the closed `limitless.exact-file-bundle/1.0` format/media-type pair inside the
signed selection. Current discovery, ordinary queries, artifact fetching, and
receiver installation remain on `1.3`; a client must not infer this descriptor
for older results or mix the two generations in one query.

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
