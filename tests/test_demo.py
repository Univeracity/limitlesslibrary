from __future__ import annotations

import json
from pathlib import Path

import pytest
from limitless_library import demo_assets
from limitless_library.catalog import seal_capsule
from limitless_library.contracts import load_json
from limitless_library.demo import DemoError, format_demo, run_demo
from limitless_library.installer import seal_recipe

ASSETS = Path(demo_assets.__file__).parent


def test_demo_runs_all_three_treatments_and_retains_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "limitless-demo"
    result = run_demo(workspace)

    assert result["exact"]["decision"] == "reuse"
    assert result["exact"]["technicalIntegrationVerified"] is True
    assert result["exact"]["runtimeAdherenceVerified"] is True
    assert result["usefulResult"]["output"]["authorization"] == "[REDACTED]"
    assert result["usefulResult"]["output"]["metadata"]["token"] == "[REDACTED]"
    assert result["method"] == {
        "decision": "instantiate",
        "treatment": "method-guided",
        "summary": "Create a non-mutating, field-name redactor for JSON-like agent audit events.",
        "sourceFilesDisclosed": False,
    }
    assert result["abstention"] == {
        "decision": "abstain",
        "reason": "no-safe-selection",
        "candidateDetailsDisclosed": False,
    }
    receipt = json.loads((workspace / "adoption-receipt.json").read_text())
    assert receipt["receiptDigest"] == result["exact"]["receiptDigest"]
    assert "observed runtime invocation" in format_demo(result)


def test_demo_refuses_to_reuse_a_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "already-here"
    workspace.mkdir()
    with pytest.raises(DemoError, match="overwrite"):
        run_demo(workspace)


def test_demo_checks_containment_before_creating_a_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "must-not-exist"
    monkeypatch.setattr(
        "limitless_library.demo.containment_readiness",
        lambda: {"status": "blocked", "reason": "Bubblewrap is unavailable"},
    )

    with pytest.raises(DemoError, match="limitless doctor"):
        run_demo(workspace)

    assert not workspace.exists()


def test_demo_authoring_records_reproduce_sealed_assets() -> None:
    capsule_root = ASSETS / "catalog" / "structured-redaction"
    receiver = ASSETS / "receiver"
    assert seal_capsule(load_json(ASSETS / "authoring" / "capsule.draft.json"), capsule_root) == load_json(
        capsule_root / "capsule.json"
    )
    assert seal_recipe(load_json(ASSETS / "authoring" / "recipe.draft.json"), receiver) == load_json(
        receiver / "recipe.json"
    )
