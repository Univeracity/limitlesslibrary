# Conformance example

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
