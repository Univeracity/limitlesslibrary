# Security policy

## Supported version

Security fixes target the current `0.1.0a1` alpha release and `main`. Alpha
status does not provide security or interface stability guarantees.

## Reporting

Do not disclose a suspected vulnerability in a public issue or discussion. Use
the repository's [private security-advisory
form](https://github.com/Univeracity/limitlesslibrary/security/advisories/new).
If that form is unavailable, contact the
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
