# Conformance example

For a first demonstration, run `./scripts/limitless` from the repository root.
It uses its own bundled redaction catalog and shows useful output plus all three
outcomes. The examples below expose the smaller primitives for inspection.

This neutral fixture demonstrates all three query outcomes:

- `exact-python.json` selects immutable Python bytes;
- `method-portable.json` receives implementation guidance without source;
- `abstain.json` returns no candidate details.

The receiver owns its installation mapping and both verifier programs. The
adherence verifier proves that receiver code imports and invokes the selected
component; the obligation verifier checks behavior and invalid inputs. Both run
with no network, no secrets, and a read-only receiver mount.

The files in `authoring/` show the pre-seal form. The catalog manifest and
receiver recipe are their content-addressed release forms.

## Run the primitives manually

From the repository root, query each outcome:

```bash
limitless query --catalog examples/catalog --request examples/requests/exact-python.json
limitless query --catalog examples/catalog --request examples/requests/method-portable.json
limitless query --catalog examples/catalog --request examples/requests/abstain.json
```

Adopt the exact result into a disposable copy of the receiver:

```bash
demo_dir=$(mktemp -d)
cp -R examples/receiver "$demo_dir/receiver"

limitless query \
  --catalog examples/catalog \
  --request examples/requests/exact-python.json \
  --output "$demo_dir/exact-decision.json"

limitless adopt \
  --catalog examples/catalog \
  --decision "$demo_dir/exact-decision.json" \
  --recipe "$demo_dir/receiver/recipe.json" \
  --receiver "$demo_dir/receiver" \
  --receipt "$demo_dir/adoption-receipt.json" \
  --owner-authorized
```

The installed `_vendor/greeting.py` and `adoption-receipt.json` can then be
inspected independently. The receipt binds the decision, recipe, exact bytes,
receiver state, verifier bytes and results, containment profile, and explicit
operator authorization.

## Service receiver and publication examples

`receiver-context.json` is a complete service receiver context for an agent on
Linux/x86_64. Review its host, target, interfaces, and allowed use before using
it with `service-query --receiver`. The files in `requests/` use the separate
local query contract. The service client constructs fresh timestamps and a
digest, so the service example contains receiver facts rather than a stale
signed query. Live discovery can abstain.

`publication/method.json` contains canonical UTF-8 method bytes, with sorted
keys and one trailing newline. To author a method in readable JSON, write a
draft and run `limitless seal-method --draft INPUT --output NEW_FILE`, then
reference the new file from a publication draft. Sealing is local and does not
publish. Object keys are canonicalized; ordered steps and sorted, unique lists
must already satisfy the method contract.
