# Security policy

## Supported version

Only the latest commit of the `0.1.0a0` pre-alpha is supported. There are no
security stability guarantees yet.

## Reporting

Do not disclose a suspected vulnerability in a public issue. Once the remote
repository exists, use its private security-advisory channel. Before then,
report it privately to the maintainer who provided this repository to you.
Include the affected record, command, operating system, expected behavior, and
a minimal reproduction that contains no secrets or third-party data.

## High-value areas

Path traversal, symlink races, overwrite behavior, containment escape,
unbounded process or protocol output, ambiguous JSON, digest substitution,
stale-decision use, and accidental secret/environment inheritance are all
security-relevant.
