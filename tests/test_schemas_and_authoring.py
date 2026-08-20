from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator
from limitless_library.catalog import LocalCatalog, seal_capsule
from limitless_library.contracts import load_json
from limitless_library.schemas import load_schema

ROOT = Path(__file__).parents[1]


def test_all_bundled_schemas_are_valid_draft_2020_12() -> None:
    schema_root = files("limitless_library.schemas")
    names = sorted(item.name for item in schema_root.iterdir() if item.name.endswith(".json"))
    assert names == [
        "adoption-receipt-0.1.schema.json",
        "capsule-0.1.schema.json",
        "decision-0.1.schema.json",
        "query-0.1.schema.json",
        "recipe-0.1.schema.json",
        "verifier-result-0.1.schema.json",
    ]
    for name in names:
        Draft202012Validator.check_schema(load_schema(name))


def test_capsule_sealing_reproduces_checked_in_manifest() -> None:
    root = ROOT / "examples" / "catalog" / "hello-component"
    draft = load_json(ROOT / "examples" / "authoring" / "capsule.draft.json")
    assert seal_capsule(draft, root) == load_json(root / "capsule.json")
    assert LocalCatalog(ROOT / "examples" / "catalog").catalog_digest.startswith("sha256:")
