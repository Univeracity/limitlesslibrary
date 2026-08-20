from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from limitless_library.catalog import LocalCatalog
from limitless_library.contracts import load_json, sha256_file
from limitless_library.installer import AdoptionError, adopt_exact_component, seal_recipe

ROOT = Path(__file__).parents[1]
CATALOG_PATH = ROOT / "examples" / "catalog"
REQUEST = ROOT / "examples" / "requests" / "exact-python.json"
RECEIVER = ROOT / "examples" / "receiver"


def _receiver(tmp_path: Path) -> Path:
    receiver = tmp_path / "receiver"
    shutil.copytree(RECEIVER, receiver)
    return receiver


def _decision(catalog: LocalCatalog) -> dict[str, object]:
    return catalog.query(load_json(REQUEST))


def test_exact_adoption_installs_exact_bytes_and_records_verified_use(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    catalog = LocalCatalog(CATALOG_PATH)
    decision = _decision(catalog)
    receipt_path = tmp_path / "adoption.json"
    receipt = adopt_exact_component(
        catalog,
        decision,
        load_json(receiver / "recipe.json"),
        receiver,
        owner_authorized=True,
        receipt_path=receipt_path,
    )
    installed = receiver / "_vendor" / "greeting.py"
    assert sha256_file(installed) == decision["selected"]["offer"]["files"][0]["digest"]
    assert receipt["disposition"] == {
        "technicalIntegrationVerified": True,
        "runtimeAdherenceVerified": True,
        "ownerAuthorization": "operator-asserted",
    }
    assert {item["kind"] for item in receipt["verifierResults"]} == {"adherence", "obligation"}
    assert json.loads(receipt_path.read_text())["receiptDigest"] == receipt["receiptDigest"]


def test_owner_authorization_is_mandatory_and_non_mutating(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    catalog = LocalCatalog(CATALOG_PATH)
    with pytest.raises(AdoptionError, match="authorization"):
        adopt_exact_component(
            catalog,
            _decision(catalog),
            load_json(receiver / "recipe.json"),
            receiver,
            owner_authorized=False,
        )
    assert not (receiver / "_vendor").exists()


def test_existing_receiver_file_is_never_overwritten(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    target = receiver / "_vendor" / "greeting.py"
    target.parent.mkdir()
    target.write_text("receiver-owned\n")
    catalog = LocalCatalog(CATALOG_PATH)
    with pytest.raises(AdoptionError, match="overwrite"):
        adopt_exact_component(
            catalog,
            _decision(catalog),
            load_json(receiver / "recipe.json"),
            receiver,
            owner_authorized=True,
        )
    assert target.read_text() == "receiver-owned\n"


def test_adherence_failure_rolls_back_new_files(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    receiver.joinpath("app.py").write_text("def render(name: str) -> str:\n    return f'Hello, {name.strip()}!'\n")
    catalog = LocalCatalog(CATALOG_PATH)
    with pytest.raises(AdoptionError, match="runtime-adherence"):
        adopt_exact_component(
            catalog,
            _decision(catalog),
            load_json(receiver / "recipe.json"),
            receiver,
            owner_authorized=True,
        )
    assert not (receiver / "_vendor" / "greeting.py").exists()


def test_changed_verifier_is_rejected_before_install(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    verifier = receiver / "verify" / "obligations.py"
    verifier.write_text(verifier.read_text() + "\n# changed\n")
    catalog = LocalCatalog(CATALOG_PATH)
    with pytest.raises(AdoptionError, match="verifier bytes differ"):
        adopt_exact_component(
            catalog,
            _decision(catalog),
            load_json(receiver / "recipe.json"),
            receiver,
            owner_authorized=True,
        )
    assert not (receiver / "_vendor").exists()


def test_recipe_sealing_binds_current_receiver_verifiers(tmp_path: Path) -> None:
    receiver = _receiver(tmp_path)
    draft = load_json(ROOT / "examples" / "authoring" / "recipe.draft.json")
    sealed = seal_recipe(draft, receiver)
    assert sealed == load_json(RECEIVER / "recipe.json")
