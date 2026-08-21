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

- `limitless.service-query/1.0`;
- `limitless.service-query-result/1.0` and `1.1`;
- `limitless.service-discovery/1.0`;
- `limitless.service-root-key-transition/1.0` and its bounded set;
- `limitless.service-profile/1.1`, official-service locator `1.0`, and local
  activation state `1.0`;
- outcome attempt/receipt `1.0`; and
- submission, transfer-grant, and immutable-release `1.0` contracts.

The packaged `limitless_library.conformance` corpora contain signed positive
vectors and declared negative mutations for the query lifecycle and root-key
rotation. These records are the public compatibility surface; private ranking,
identity, policy evaluation, persistence, and deployment records are not.

See [Managed-service connector](MANAGED-SERVICE.md) for one-action official
activation, advanced profiles, and the HTTPS boundary.
