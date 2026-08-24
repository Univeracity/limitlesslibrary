from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from limitless_library.catalog import CatalogError, LocalCatalog
from limitless_library.contracts import load_json, sha256_json, without

ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "examples" / "catalog"
REQUESTS = ROOT / "examples" / "requests"


def test_example_catalog_selects_exact_method_and_non_disclosing_abstention() -> None:
    catalog = LocalCatalog(CATALOG)
    exact = catalog.query(load_json(REQUESTS / "exact-python.json"))
    method = catalog.query(load_json(REQUESTS / "method-portable.json"))
    abstain = catalog.query(load_json(REQUESTS / "abstain.json"))

    assert (exact["decision"], exact["treatment"], exact["selected"]["offer"]["kind"]) == (
        "reuse",
        "exact-adoption",
        "exact-component",
    )
    assert (method["decision"], method["treatment"], method["selected"]["offer"]["kind"]) == (
        "instantiate",
        "method-guided",
        "method",
    )
    assert method["selected"]["offer"]["files"] is None
    assert method["selected"]["offer"]["method"]["steps"]
    assert set(exact["selected"]["offer"]) == {"id", "kind", "taskKind", "files", "method"}
    assert abstain == {
        "schemaVersion": "limitless.decision/0.1",
        "decision": "abstain",
        "treatment": "abstain",
        "requestDigest": abstain["requestDigest"],
        "catalogDigest": catalog.catalog_digest,
        "selected": None,
        "reason": "no-safe-selection",
        "decisionDigest": abstain["decisionDigest"],
    }


def test_query_is_deterministic_and_bound_to_exact_request() -> None:
    catalog = LocalCatalog(CATALOG)
    request = load_json(REQUESTS / "exact-python.json")
    first = catalog.query(request)
    assert catalog.query(copy.deepcopy(request)) == first
    changed = copy.deepcopy(request)
    changed["tenantScope"] = "another-tenant"
    with pytest.raises(CatalogError, match="not bound"):
        catalog.validate_decision(first, request=changed)


def test_changed_exact_bytes_invalidate_catalog(tmp_path: Path) -> None:
    copied = tmp_path / "catalog"
    shutil.copytree(CATALOG, copied)
    payload = copied / "hello-component" / "payload" / "greeting.py"
    payload.write_text(payload.read_text() + "\n# changed\n")
    with pytest.raises(CatalogError, match="digest differs"):
        LocalCatalog(copied)


def test_equal_priority_ambiguity_abstains_without_candidate_details(tmp_path: Path) -> None:
    copied = tmp_path / "catalog"
    shutil.copytree(CATALOG, copied)
    manifest = copied / "hello-component" / "capsule.json"
    capsule = json.loads(manifest.read_text())
    capsule["offers"][1]["priority"] = 100
    capsule["offers"][1]["compatibility"]["constraints"] = ["language:python", "runtime:any"]
    capsule["offers"][1]["compatibility"]["toolchain"] = {"python": ["3.12"]}
    capsule["capsuleDigest"] = sha256_json(without(capsule, "capsuleDigest"))
    manifest.write_text(json.dumps(capsule))
    decision = LocalCatalog(copied).query(load_json(REQUESTS / "exact-python.json"))
    assert decision["decision"] == "abstain"
    assert decision["selected"] is None
    assert decision["reason"] == "no-safe-selection"


def test_objective_breaks_only_a_unique_equal_priority_lexical_tie(tmp_path: Path) -> None:
    copied = tmp_path / "catalog"
    shutil.copytree(CATALOG, copied)
    manifest = copied / "hello-component" / "capsule.json"
    capsule = json.loads(manifest.read_text())
    capsule["offers"][1]["priority"] = 100
    capsule["offers"][1]["compatibility"]["constraints"] = ["language:python", "runtime:any"]
    capsule["offers"][1]["compatibility"]["toolchain"] = {"python": ["3.12"]}
    capsule["capsuleDigest"] = sha256_json(without(capsule, "capsuleDigest"))
    manifest.write_text(json.dumps(capsule))
    request = load_json(REQUESTS / "exact-python.json")
    request["objective"] = "Normalize a non-empty name and render a deterministic greeting."

    decision = LocalCatalog(copied).query(request)

    assert decision["decision"] == "instantiate"
    assert decision["selected"]["offer"]["id"] == "offer:hello-portable-method"


def test_objective_does_not_force_an_unmatched_equal_priority_choice(tmp_path: Path) -> None:
    copied = tmp_path / "catalog"
    shutil.copytree(CATALOG, copied)
    manifest = copied / "hello-component" / "capsule.json"
    capsule = json.loads(manifest.read_text())
    capsule["offers"][1]["priority"] = 100
    capsule["offers"][1]["compatibility"]["constraints"] = ["language:python", "runtime:any"]
    capsule["offers"][1]["compatibility"]["toolchain"] = {"python": ["3.12"]}
    capsule["capsuleDigest"] = sha256_json(without(capsule, "capsuleDigest"))
    manifest.write_text(json.dumps(capsule))
    request = load_json(REQUESTS / "exact-python.json")
    request["objective"] = "Tune a database connection pool."

    decision = LocalCatalog(copied).query(request)

    assert decision["decision"] == "abstain"
    assert decision["selected"] is None


def test_revoked_and_unauthorized_offers_are_ineligible(tmp_path: Path) -> None:
    copied = tmp_path / "catalog"
    shutil.copytree(CATALOG, copied)
    manifest = copied / "hello-component" / "capsule.json"
    capsule = json.loads(manifest.read_text())
    for offer in capsule["offers"]:
        offer["policy"]["state"] = "revoked"
    capsule["capsuleDigest"] = sha256_json(without(capsule, "capsuleDigest"))
    manifest.write_text(json.dumps(capsule))
    decision = LocalCatalog(copied).query(load_json(REQUESTS / "exact-python.json"))
    assert decision["decision"] == "abstain"
