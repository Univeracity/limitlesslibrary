from __future__ import annotations

import json
from pathlib import Path

import pytest

from limitless_library import method_drafts
from limitless_library.catalog import LocalCatalog
from limitless_library.method_drafts import DraftError, default_draft_policy, load_draft, register_draft


def content(name="Atomic index updates", **extra):
    return {
        "name": name,
        "steps": ["Stage the next index before replacing the active index."],
        "verify": ["The active index addresses the expected bytes."],
        **extra,
    }


def register(root: Path, value: dict, **extra):
    return register_draft(root / "drafts", root / "catalog", value, policy=default_draft_policy(), **extra)


def test_generic_kernel_registers_without_an_omarchy_dependency_and_keeps_record_bytes(tmp_path: Path) -> None:
    first = register(tmp_path, content())
    record = load_draft(tmp_path / "drafts", first["draftRef"])
    assert record["taskKind"] == "general-work"
    assert record["requestedDestination"] == "local"
    files = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")}
    assert register(tmp_path, content()) == {**first, "status": "duplicate"}
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")} == files
    capsule = next((tmp_path / "catalog").glob("*/capsule.json"))
    assert json.loads(capsule.read_text())["offers"][0]["compatibility"] == {"constraints": [], "toolchain": {}}
    assert LocalCatalog(tmp_path / "catalog")


def test_revision_retires_only_old_projection_and_preserves_parent_record(tmp_path: Path) -> None:
    first = register(tmp_path, content())
    record_path = tmp_path / "drafts/records" / (first["draftRef"].split(":")[1] + ".json")
    original = record_path.read_bytes()
    second = register(
        tmp_path,
        content(supersedes=first["draftRef"], steps=["Validate the staged index and then replace the active pointer."]),
    )
    child = load_draft(tmp_path / "drafts", second["draftRef"])
    parent = load_draft(tmp_path / "drafts", first["draftRef"])
    assert child["lineageId"] == parent["lineageId"] and child["revision"] == parent["revision"] + 1
    assert record_path.read_bytes() == original
    assert len(list((tmp_path / "catalog").glob("*/capsule.json"))) == 1
    with pytest.raises(DraftError, match="no longer current"):
        register(tmp_path, content("Third revision", supersedes=first["draftRef"]))


def test_callback_failure_cannot_destroy_previous_revision_or_leave_a_new_record(tmp_path: Path) -> None:
    first = register(tmp_path, content())
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")}

    def unavailable(_root, _record):
        raise ValueError("sharing state unavailable")

    with pytest.raises(DraftError, match="could not be initialized"):
        register(
            tmp_path,
            content(supersedes=first["draftRef"], steps=["Check the replacement before pointer activation."]),
            initialize=unavailable,
        )
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")} == before
    assert register(tmp_path, content())["status"] == "duplicate"


def test_full_registry_remains_readable_and_duplicate_still_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(method_drafts, "MAX_DRAFTS", 2)
    first = register(tmp_path, content())
    second = register(tmp_path, content("Immutable method lineage"))
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")}
    with pytest.raises(DraftError, match="supported bound"):
        register(tmp_path, content("Third distinct method"))
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")} == before
    assert register(tmp_path, content()) == {**first, "status": "duplicate"}
    assert load_draft(tmp_path / "drafts", second["draftRef"])


def test_invalid_public_authorization_never_creates_a_registry(tmp_path: Path) -> None:
    policy = {**default_draft_policy(), "defaultDestination": "public"}
    with pytest.raises(DraftError, match="authorization"):
        register_draft(tmp_path / "drafts", tmp_path / "catalog", content(), policy=policy)
    assert not list(tmp_path.iterdir())


def test_successful_revision_can_be_retried_without_creating_or_reactivating_records(tmp_path: Path) -> None:
    first = register(tmp_path, content())
    revision = content(supersedes=first["draftRef"], steps=["Recheck the index identity after activating its pointer."])
    second = register(tmp_path, revision)
    original = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")}
    assert register(tmp_path, revision) == {**second, "status": "duplicate"}
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")} == original


def test_retry_repairs_missing_projection_without_modifying_its_record(tmp_path: Path) -> None:
    import shutil

    first = register(tmp_path, content())
    record_path = tmp_path / "drafts/records" / (first["draftRef"].split(":")[1] + ".json")
    original = record_path.read_bytes()
    projection = next((tmp_path / "catalog").iterdir())
    shutil.rmtree(projection)
    assert register(tmp_path, content()) == {**first, "status": "duplicate"}
    assert (projection / "capsule.json").is_file() and record_path.read_bytes() == original


def test_revision_retry_completes_interrupted_retirement_without_new_id(tmp_path: Path, monkeypatch) -> None:
    first = register(tmp_path, content())
    retire = method_drafts._retire_projection

    def interrupted(catalog, reference):
        if reference == first["draftRef"]:
            raise OSError("interrupted retirement")
        return retire(catalog, reference)

    monkeypatch.setattr(method_drafts, "_retire_projection", interrupted)
    revision = content(supersedes=first["draftRef"], steps=["Verify the new index before atomically activating it."])
    with pytest.raises(DraftError):
        register(tmp_path, revision)
    records = list((tmp_path / "drafts/records").glob("*.json"))
    assert len(records) == 2 and len(list((tmp_path / "catalog").iterdir())) == 2
    before = {p.name: p.read_bytes() for p in records}
    monkeypatch.setattr(method_drafts, "_retire_projection", retire)
    duplicate = register(tmp_path, revision)
    assert duplicate["status"] == "duplicate" and duplicate["draftRef"] != first["draftRef"]
    assert {p.name: p.read_bytes() for p in records} == before
    assert len(list((tmp_path / "catalog").iterdir())) == 1
