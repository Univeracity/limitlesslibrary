# Security policy

## Supported version

Only the latest commit of the `0.1.0a0` pre-alpha is supported. There are no
security stability guarantees yet.

## Reporting

Do not disclose a suspected vulnerability in a public issue or discussion. Use
the repository's [private security-advisory
form](https://github.com/Univeracity/limitlesslibrary/security/advisories/new).
If that form is unavailable during the pre-release transition, contact the
repository owner through a previously established private channel.

Include the affected version or commit, operating system, expected behavior,
impact, and a minimal reproduction. Do not include credentials, private
catalog records, receiver source code, adoption evidence, or third-party data.
Reports are acknowledged after review; disclosure timing is coordinated when a
fix is required.

## High-value areas

Path traversal, symlink races, overwrite behavior, containment escape,
unbounded process or protocol output, ambiguous JSON, digest substitution,
stale-decision use, and accidental secret/environment inheritance are all
security-relevant.
