# Backward compatibility

Installed clients must continue using their existing local query and signed
service contracts without a mandatory update. New tools are additive. New
objective-query consent and private outcome files do not rewrite old settings,
capture identities, draft revisions, sharing state, or publication signatures.

`python scripts/verify-legacy-compatibility.py` runs unchanged 0.1.0a0 and
0.1.0a1 client code from pinned public Git commits against the candidate MCP
server. It compares complete exact, method, and abstention decisions with each
original client's own local baseline. Both clients also consume a capture
written by the original 0.1.0a1 producer. Queries must leave owner state intact.
The test does not download or contact a service; the checkout needs full Git
history. CI runs it on each supported Python version.

Pass `--omarchy-root /path/to/limitless-omarchy` to test both unchanged clients
against the candidate adapter too, and test original 0.2.1 draft state through
the shared kernel. The original plugin writes a draft, the candidate preserves
its duplicate identity and writes a revision, the original plugin reads and
revises that record, and the candidate reads the next revision. Original record,
settings, and sharing bytes must remain unchanged.

This is source interoperability evidence. A coordinated release also requires
tests against its actual installed wheels and bundles, existing activation and
publication identities, all supported signed service result generations, and
native user journeys. Keep historical release artifacts immutable and report
these gates separately; a passing source test does not establish deployment
continuity or prove useful receiver outcomes.
