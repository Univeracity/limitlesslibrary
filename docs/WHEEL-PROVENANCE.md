# Public core wheel source evidence

The `0.1.0a1` core wheel distributed with the Omarchy plugin is a pure-Python
package. Its exact SHA-256 is
`1f776299c684e1b52430585b640917a37ca88eac9ef0db0414ad0e18e8094986`.
Its package sources are public at commit
[`b9249e8de3e2cf558b70719dcd6e7a2ec44dd352`](https://github.com/Univeracity/limitlesslibrary/tree/b9249e8de3e2cf558b70719dcd6e7a2ec44dd352/src/limitless_library).

[The build recipe](releases/0.1.0a1-wheel.json) records the source commit,
its timestamp, the exact wheel digest, and the pinned build tools.
The [source evidence workflow](../.github/workflows/wheel-provenance.yml):

1. Checks out that exact public source commit and verifies its identity.
2. Builds two fresh Git archives with the pinned tools and the commit timestamp
   as `SOURCE_DATE_EPOCH`.
3. Requires both complete wheel digests to match the wheel already distributed.
   This covers generated metadata and entry points as well as package code.
4. Compares every package file against the source archive, including Python,
   schemas, conformance resources, and `py.typed`; the report records their hashes.
5. On `main`, signs a statement binding that wheel digest to the explicit source
   commit, tree, build tools, two rebuild results, and public workflow run.
   A separate job verifies the signature before publishing the evidence artifact.

This is a new reproduction of the existing wheel. It does not claim to be an
attestation recorded during its original release build or a security audit.
The signing workflow's own commit is separately recorded from the historical
source commit used to build the wheel.

## Verify the distributed wheel

Download the wheel from the
[`v0.1.0a1` release](https://github.com/Univeracity/limitlesslibrary/releases/tag/v0.1.0a1).
Using a current GitHub CLI:

```sh
gh attestation verify limitless_library-0.1.0a1-py3-none-any.whl \
  --repo Univeracity/limitlesslibrary \
  --signer-workflow Univeracity/limitlesslibrary/.github/workflows/wheel-provenance.yml \
  --predicate-type https://github.com/Univeracity/limitlesslibrary/releases/wheel-build/v1 \
  --format json
```

Inspect the verified statement's source commit and wheel digest against the
plugin's `runtime/bundle.json`. The predicate type above identifies the version 1
JSON build report emitted by `scripts/reproduce-release-wheel.py`.
Successful runs retain the rebuilt wheel, report, Sigstore bundle, and verification
result as the `attested-core-wheel` artifact. Published release evidence bundles
can also be verified offline with GitHub CLI's `--bundle` option.

## Reproduce locally

Use Python 3.12 with `pip==26.2.1`, `build==1.5.0`, `setuptools==83.0.0`, and
`wheel==0.48.0`. Keep the build tooling checkout separate from a detached checkout
of the historical source commit, then run:

```sh
python scripts/reproduce-release-wheel.py \
  --source-root /path/to/historical-source \
  --recipe docs/releases/0.1.0a1-wheel.json \
  --output /path/to/reproduction-output
```
