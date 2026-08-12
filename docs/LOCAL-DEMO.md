# Local lifecycle demo

Run the complete lifecycle directly from a source checkout:

```bash
./scripts/limitless
```

The launcher prepares an isolated local environment on first use and retains
the initial evidence under `.limitless/quickstart`. No environment activation
or manual package installation is required. Run `./scripts/limitless doctor`
for an actionable containment check.

Choose a separate evidence path when needed:

```bash
./scripts/limitless demo --workspace ./limitless-demo
```

The workspace must not already exist. Limitless creates it, copies a clean
receiver fixture, and leaves these inspectable artifacts:

| Artifact | What it establishes |
| --- | --- |
| `exact-decision.json` | The request, catalog, capsule, and exact offer selected before work |
| `receiver/_vendor/structured_redaction.py` | The content-addressed bytes installed without overwrite |
| `adoption-receipt.json` | Bound installation, containment, receiver checks, invocation, and authorization evidence |
| `method-decision.json` | Portable implementation guidance without source-file disclosure |
| `abstention-decision.json` | The stable response when no safe match can be selected |

The exact component recursively redacts configured field names from JSON-like
agent audit events without mutating the input. The receiver's adherence check
rehashes the installed file and instruments its call path to prove that the
receiver actually invokes it. A separate obligation check covers nested data,
arrays, preserved fields, input immutability, and invalid input. Both execute
with no network, no inherited secrets, a read-only receiver mount, and bounded
resources.

This deliberately scoped component is meaningful but not presented as a
security product. It cannot discover credentials embedded in arbitrary strings
and should not replace context-specific data-loss controls.

Run without `--workspace` for a disposable demonstration, or add
`--format json` for machine-readable output:

```bash
./scripts/limitless demo --format json
```

Every demo asset is packaged under `limitless_library.demo_assets`; the command
therefore behaves the same from an installed wheel as it does in the source
checkout.
