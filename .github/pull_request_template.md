## Summary

Describe the receiver outcome, trust-boundary behavior, or documentation changed and why.

## Verification

- [ ] Relevant unit and lifecycle tests pass on Python 3.11 and 3.12.
- [ ] Trust-boundary changes include at least one rejection or fail-closed test.
- [ ] Public schemas, protocol documentation, and examples are updated when applicable.
- [ ] No credentials, receiver source, private catalog data, internal evidence, or generated receipts are included.
- [ ] Package contents were inspected when distribution or bundled assets changed.

## Public information review

Does this change expose new public information? **No / Yes**

If yes, identify the newly public design, operational detail, example, evidence,
or roadmap material and explain why publication is intentional. Internal
strategy and private operational context remain outside this repository unless
their publication is explicitly authorized.

## Compatibility and security

Call out schema changes, migrations, new permissions, containment changes,
security implications, and known limits. Write `None` when there is no impact.
