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
