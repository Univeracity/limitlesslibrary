from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from limitless_library.catalog import CatalogError, LocalCatalog
from limitless_library.catalog_snapshot import CatalogSnapshot
from limitless_library.contracts import canonical_json_bytes, load_json
from limitless_library.method_capture import CapturedMethodCatalog, register_method
from limitless_library.method_projection import project_method_capsule

ROOT = Path(__file__).parents[1]


def write_method(root: Path, name: str) -> Path:
    directory = root / name
    directory.mkdir()
    capsule = project_method_capsule(
        capsule_id="capsule:" + name,
        offer_id="offer:" + name,
        version="1.0.0",
        title=name,
        task_kind="general-work",
        method={"summary": name, "steps": ["Apply the procedure."], "verification": ["Receiver checks pass."]},
        compatibility={"constraints": [], "toolchain": {}},
    )
    (directory / "capsule.json").write_bytes(canonical_json_bytes(capsule))
    return directory


def test_live_snapshot_observes_external_addition_retirement_and_empty_source_without_writes(tmp_path: Path) -> None:
    source = CatalogSnapshot(tmp_path)
    empty = source.snapshot()
    assert source.snapshot() is empty
    directory = write_method(tmp_path, "symlink-safety")
    loaded = source.snapshot()
    assert loaded.catalog_digest != empty.catalog_digest
    assert source.snapshot() is loaded
    shutil.rmtree(directory)
    assert source.snapshot().catalog_digest == empty.catalog_digest
    assert list(tmp_path.iterdir()) == []


def test_snapshot_preserves_original_decision_and_warm_cache(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "examples/catalog", tmp_path / "catalog")
    source = CatalogSnapshot(tmp_path / "catalog")
    original = LocalCatalog(tmp_path / "catalog")
    request = load_json(ROOT / "examples/requests/exact-python.json")
    loaded = source.snapshot()
    assert loaded.query(request) == original.query(request)
    assert source.snapshot() is loaded


def test_changed_exact_bytes_cannot_be_served_from_the_warm_snapshot_even_with_restored_mtime(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    shutil.copytree(ROOT / "examples/catalog", root)
    source = CatalogSnapshot(root)
    source.snapshot()
    path = root / "hello-component/payload/greeting.py"
    before = path.stat()
    path.write_bytes(path.read_bytes().replace(b"Hello", b"HELLO"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(CatalogError, match="digest differs"):
        source.snapshot()


def test_manifest_corruption_does_not_reuse_the_preceding_selection(tmp_path: Path) -> None:
    directory = write_method(tmp_path, "symlink-safety")
    source = CatalogSnapshot(tmp_path)
    source.snapshot()
    (directory / "capsule.json").write_text("{}")
    with pytest.raises(CatalogError):
        source.snapshot()


def test_writer_lock_is_nonblocking_and_reader_never_creates_it(tmp_path: Path) -> None:
    import fcntl

    write_method(tmp_path, "symlink-safety")
    lock_path = tmp_path / ".lock"
    source = CatalogSnapshot(tmp_path, lock_path=lock_path)
    source.snapshot()
    assert not lock_path.exists()
    with lock_path.open("w") as writer:
        fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(CatalogError, match="unavailable"):
            source.snapshot()
        fcntl.flock(writer, fcntl.LOCK_UN)
        assert source.snapshot()


def test_unsafe_exact_parent_and_deleted_base_have_no_stale_fallback(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    shutil.copytree(ROOT / "examples/catalog", root)
    source = CatalogSnapshot(root)
    source.snapshot()
    payload = root / "hello-component/payload"
    moved = root / "hello-component/original-payload"
    payload.rename(moved)
    payload.symlink_to(moved, target_is_directory=True)
    with pytest.raises(CatalogError, match="symlink"):
        source.snapshot()
    shutil.rmtree(root)
    with pytest.raises(CatalogError):
        source.snapshot()


def test_fifo_lock_is_rejected_without_waiting_for_a_writer(tmp_path: Path) -> None:
    path = tmp_path / ".lock"
    os.mkfifo(path)
    with pytest.raises(CatalogError, match="unsafe"):
        CatalogSnapshot(tmp_path, lock_path=path).snapshot()


def test_valid_private_captures_survive_a_damaged_optional_base_with_partial_coverage(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    source = CatalogSnapshot(catalog)
    methods = tmp_path / "methods"
    register_method(
        methods,
        {
            "title": "Observed adoption",
            "taskKind": "receiver-verification",
            "method": load_json(ROOT / "examples/publication/method.json"),
            "observedOutcome": "Receiver checks pass.",
            "platform": "any",
        },
    )
    combined = CapturedMethodCatalog(LocalCatalog.empty(catalog), methods, catalog_source=source.snapshot)
    shutil.rmtree(catalog)
    result, complete = combined.query_objective(
        "Observed adoption",
        receiver={"constraints": [], "toolchain": {}},
        requested_uses=("adopt",),
        tenant_scopes=("private",),
        evaluated_at="2026-10-13T04:00:00Z",
    )
    assert not complete and result is not None
    assert result["decision"]["selected"]["offer"]["id"].startswith("offer:captured.")
