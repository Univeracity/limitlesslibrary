from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from limitless_library.catalog import CatalogError, LocalCatalog
from limitless_library.contracts import canonical_json_bytes, load_json, sha256_json
from limitless_library.mcp_protocol import modern_metadata
from limitless_library.mcp_server import OBJECTIVE_TOOL_NAME, REGISTER_METHOD_TOOL_NAME, TOOL_NAME, _dispatcher
from limitless_library.method_capture import (
    CapturedMethodCatalog,
    MethodCaptureError,
    captured_method_capsules,
    query_with_captured_methods,
    register_method,
    sync_methods,
)
from limitless_library.method_projection import project_method_capsule
from limitless_library.publication import PublicationError, _new_state, _source_descriptor
from limitless_library.service_contracts import validate_source_free_method
from limitless_library.service_identity import InstallationSigner

ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "examples" / "catalog"
POLICY_DIGEST = "sha256:" + "5" * 64


def _method() -> dict:
    return {
        "title": "Verify observed adoption",
        "taskKind": "receiver-verification",
        "method": load_json(ROOT / "examples" / "publication" / "method.json"),
        "observedOutcome": "Receiver checks passed and the supplied component was invoked.",
        "platform": "linux",
    }


def _call(name: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": modern_metadata(client_name="method-test", client_version="1"),
        },
    }


def large_method() -> dict:
    value = _method()
    value["method"] = {
        "summary": "Receiver verification",
        "steps": [
            {"index": index + 1, "instruction": "界" * 400, "check": "fact-present", "expected": "界" * 240}
            for index in range(16)
        ],
        "constraints": [f"{index:02d}" + "界" * 238 for index in range(16)],
        "evaluation": [f"{index:02d}" + "界" * 238 for index in range(16)],
        "limitations": [f"{index:02d}" + "界" * 238 for index in range(16)],
    }
    validate_source_free_method(value["method"])
    return value


def test_new_capture_never_creates_records_original_installed_readers_cannot_read(tmp_path: Path) -> None:
    store = tmp_path / "methods"
    with pytest.raises(MethodCaptureError, match="64 KiB"):
        register_method(store, large_method())
    assert not store.exists()


def test_previously_written_large_capture_can_be_recovered_without_rewriting_it(tmp_path: Path) -> None:
    value = large_method()
    record_digest = sha256_json(value)
    store = tmp_path / "methods"
    directory = store / record_digest[7:]
    directory.mkdir(parents=True, mode=0o700)
    store.chmod(0o700)
    (store / ".register.lock").touch(mode=0o600)
    capture = (
        canonical_json_bytes(
            {"schemaVersion": "limitless.method-capture/0.1", "methodRef": "method:" + record_digest[7:], **value}
        )
        + b"\n"
    )
    assert 64 * 1024 < len(capture) < 128 * 1024
    method = canonical_json_bytes(value["method"]) + b"\n"
    (directory / "capture.json").write_bytes(capture)
    (directory / "method.json").write_bytes(method)
    (directory / "capture.json").chmod(0o600)
    (directory / "method.json").chmod(0o600)
    projected = captured_method_capsules(store)
    assert len(projected) == 1
    guidance = projected[0]["offers"][0]["method"]
    assert len(guidance["steps"]) == 16 and len(guidance["verification"]) == 48
    assert (directory / "capture.json").read_bytes() == capture
    assert (directory / "method.json").read_bytes() == method


def test_higher_priority_capture_cannot_replace_a_working_legacy_catalog_selection(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    directory = root / "baseline"
    directory.mkdir(parents=True)
    baseline = project_method_capsule(
        capsule_id="capsule:receiver-baseline",
        offer_id="offer:receiver-baseline",
        version="1.0.0",
        title="Known receiver baseline",
        task_kind="receiver-verification",
        method={
            "summary": "Record receiver startup.",
            "steps": ["Inspect receiver startup."],
            "verification": ["Receiver startup is observed."],
        },
        compatibility={"constraints": ["linux"], "toolchain": {}},
        priority=100,
    )
    (directory / "capsule.json").write_bytes(canonical_json_bytes(baseline))
    catalog = LocalCatalog(root)
    request = {
        "schemaVersion": "limitless.query/0.1",
        "taskKind": "receiver-verification",
        "receiver": {"constraints": ["linux"], "toolchain": {}},
        "requestedUse": "instantiate",
        "tenantScope": "private",
        "evaluatedAt": "2026-10-13T04:00:00Z",
    }
    original = catalog.query(request)
    store = tmp_path / "methods"
    register_method(store, _method())
    combined = CapturedMethodCatalog(catalog, store)
    assert combined.query(request) == original
    modern, complete = combined.query_objective(
        "Verify observed adoption",
        receiver=request["receiver"],
        requested_uses=("instantiate",),
        tenant_scopes=("private",),
        evaluated_at=request["evaluatedAt"],
    )
    assert complete and modern["decision"]["selected"]["offer"]["id"].startswith("offer:captured.")


def test_damaged_optional_store_preserves_legacy_abstention_and_reports_partial_modern_coverage(tmp_path: Path) -> None:
    catalog = LocalCatalog.empty(tmp_path)
    store = tmp_path / "methods"
    captured = register_method(store, _method())
    (store / captured["methodRef"][7:] / "capture.json").write_text("{}")
    combined = CapturedMethodCatalog(catalog, store)
    request = {
        "schemaVersion": "limitless.query/0.1",
        "taskKind": "receiver-verification",
        "receiver": {"constraints": ["linux"], "toolchain": {}},
        "requestedUse": "instantiate",
        "tenantScope": "private",
        "evaluatedAt": "2026-10-13T04:00:00Z",
    }
    assert combined.query(request) == catalog.query(request)
    match, complete = combined.query_objective(
        "Observed adoption",
        receiver=request["receiver"],
        requested_uses=("instantiate",),
        tenant_scopes=("private",),
        evaluated_at=request["evaluatedAt"],
    )
    assert match is None and not complete


def test_generic_mcp_keeps_query_first_and_registers_one_local_method(tmp_path: Path) -> None:
    store = tmp_path / "methods"
    dispatcher = _dispatcher(LocalCatalog(CATALOG), method_store=store)
    names = [
        tool["name"]
        for tool in dispatcher.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"_meta": modern_metadata(client_name="method-test", client_version="1")},
            }
        )["result"]["tools"]
    ]
    assert names == [TOOL_NAME, REGISTER_METHOD_TOOL_NAME]
    assert "After completing and checking" in dispatcher.instructions

    request = load_json(ROOT / "examples" / "requests" / "exact-python.json")
    assert dispatcher.handle(_call(TOOL_NAME, request))["result"]["structuredContent"]["decision"] == "reuse"
    first = dispatcher.handle(_call(REGISTER_METHOD_TOOL_NAME, _method()))["result"]["structuredContent"]
    second = dispatcher.handle(_call(REGISTER_METHOD_TOOL_NAME, _method()))["result"]["structuredContent"]
    assert first["status"] == "registered"
    assert first["destination"] == first["submission"] == "local"
    assert second == {**first, "status": "duplicate"}
    folder = store / first["methodRef"].split(":", 1)[1]
    assert len(list(store.glob("[0-9a-f]*"))) == 1
    assert not (folder / "publication.json").exists()
    assert json.loads((folder / "capture.json").read_text())["observedOutcome"] == _method()["observedOutcome"]
    assert folder.stat().st_mode & 0o077 == 0
    assert (folder / "method.json").stat().st_mode & 0o077 == 0
    assert dispatcher.handle(_call(TOOL_NAME, request))["result"]["structuredContent"]["decision"] == "reuse"


def test_public_mode_prepares_canonical_method_and_retries_without_duplicate_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = tmp_path / "methods"
    captured = register_method(store, _method(), public_policy_digest=POLICY_DIGEST, schedule=False)
    folder = store / captured["methodRef"].split(":", 1)[1]
    method = validate_source_free_method(json.loads((folder / "method.json").read_text()))
    assert method["summary"] == _method()["method"]["summary"]
    assert _source_descriptor("method", "method.json", base=folder)["role"] == "method"
    draft = json.loads((folder / "publication.json").read_text())
    assert draft["rights"] == {"license": "CC0-1.0", "allowedUses": ["derive-method"], "hasAuthority": True}
    assert draft["compatibility"]["verifiedTargets"] == []
    assert draft["evidenceDigests"] != []
    signer = InstallationSigner.generate()
    state = _new_state(
        draft=draft,
        draft_path=folder / "publication.json",
        service_id="service:fixture",
        policy={"revision": "policy:1", "digest": POLICY_DIGEST},
        signer=signer,
        publisher={
            "publisherId": "installation:" + "8" * 32,
            "authorityId": "installation:" + "8" * 32,
            "keyId": signer.key_id,
            "generation": 1,
        },
        now=datetime(2026, 9, 23, tzinfo=UTC),
    )
    assert state["intent"]["candidate"]["treatment"] == "source-free-method"
    calls: list[Path] = []
    monkeypatch.setattr(
        "limitless_library.method_capture.activated_service_connector",
        lambda: SimpleNamespace(profile=SimpleNamespace(service_id="service:fixture")),
    )
    monkeypatch.setattr(
        "limitless_library.method_capture.installation_publisher_authority",
        lambda **_: (object(), {"publisherId": "publisher:fixture"}),
    )

    def publish(_connector: object, **kwargs: object) -> dict:
        calls.append(Path(kwargs["draft_path"]))
        assert kwargs["accepted_publication_policy_digest"] == POLICY_DIGEST
        return {"admissionState": "active"}

    monkeypatch.setattr("limitless_library.method_capture.publish_draft", publish)
    assert sync_methods(store, POLICY_DIGEST) == {"processed": 1, "submitted": 1, "attention": 0}
    assert sync_methods(store, POLICY_DIGEST) == {"processed": 0, "submitted": 0, "attention": 0}
    assert calls == [folder / "publication.json"]
    assert (
        register_method(store, _method(), public_policy_digest=POLICY_DIGEST, schedule=False)["submission"] == "active"
    )


def test_public_policy_drift_preserves_capture_for_later_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / "methods"
    captured = register_method(store, _method(), public_policy_digest=POLICY_DIGEST, schedule=False)
    monkeypatch.setattr(
        "limitless_library.method_capture.activated_service_connector",
        lambda: SimpleNamespace(profile=SimpleNamespace(service_id="service:fixture")),
    )
    monkeypatch.setattr("limitless_library.method_capture.installation_publisher_authority", lambda **_: (object(), {}))

    def changed(_connector: object, **_kwargs: object) -> dict:
        raise PublicationError("publication policy changed")

    monkeypatch.setattr("limitless_library.method_capture.publish_draft", changed)
    assert sync_methods(store, POLICY_DIGEST) == {"processed": 1, "submitted": 0, "attention": 1}
    assert (
        register_method(store, _method(), public_policy_digest=POLICY_DIGEST, schedule=False)["submission"]
        == "policy-attention"
    )
    monkeypatch.setattr(
        "limitless_library.method_capture.publish_draft", lambda *_args, **_kwargs: {"admissionState": "active"}
    )
    assert sync_methods(store, "sha256:" + "6" * 64)["submitted"] == 1
    assert (
        register_method(store, _method(), public_policy_digest=POLICY_DIGEST, schedule=False)["methodRef"]
        == captured["methodRef"]
    )


def test_invalid_method_and_bad_public_authority_never_create_records(tmp_path: Path) -> None:
    store = tmp_path / "methods"
    invalid = _method()
    invalid["method"]["steps"][0]["index"] = 2
    with pytest.raises(MethodCaptureError, match="source-free method contract"):
        register_method(store, invalid)
    with pytest.raises(MethodCaptureError, match="reviewed policy digest"):
        register_method(store, _method(), public_policy_digest="not-a-digest")
    assert not store.exists()


def test_unavailable_background_worker_is_visible_and_preserves_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("limitless_library.method_capture.schedule_submission", lambda *_args: False)
    store = tmp_path / "methods"
    result = register_method(store, _method(), public_policy_digest=POLICY_DIGEST)
    assert result["destination"] == "public"
    assert result["submission"] == "retryable"
    assert (store / result["methodRef"].split(":", 1)[1] / "publication.json").exists()


def test_stdio_mcp_lists_capture_and_requires_explicit_public_settings(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    command = [
        sys.executable,
        "-m",
        "limitless_library.mcp_server",
        "--catalog",
        str(CATALOG),
        "--method-store",
        str(tmp_path / "methods"),
    ]
    bad = subprocess.run(
        command + ["--submit-methods-publicly"],
        input="",
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )
    assert bad.returncode == 2
    assert not (tmp_path / "methods").exists()
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": modern_metadata(client_name="method-test", client_version="1")},
        },
        _call(REGISTER_METHOD_TOOL_NAME, _method()),
        _call(TOOL_NAME, _captured_query()),
    ]
    good = subprocess.run(
        command,
        input="".join(json.dumps(item) + "\n" for item in messages),
        text=True,
        capture_output=True,
        env=environment,
        check=True,
    )
    responses = [json.loads(line) for line in good.stdout.splitlines()]
    assert [tool["name"] for tool in responses[0]["result"]["tools"]] == [
        TOOL_NAME,
        OBJECTIVE_TOOL_NAME,
        REGISTER_METHOD_TOOL_NAME,
    ]
    assert responses[1]["result"]["structuredContent"]["destination"] == "local"
    assert responses[2]["result"]["structuredContent"]["decision"] == "instantiate"


def _captured_query() -> dict:
    return {
        "schemaVersion": "limitless.query/0.1",
        "objective": "Verify observed adoption",
        "taskKind": "receiver-verification",
        "receiver": {"constraints": ["linux"], "toolchain": {}},
        "requestedUse": "instantiate",
        "tenantScope": "private",
        "evaluatedAt": "2026-10-12T00:00:00Z",
    }


def test_capture_is_immediately_searchable_without_changing_existing_store_or_catalog(tmp_path: Path) -> None:
    catalog = LocalCatalog(CATALOG)
    original_digest = catalog.catalog_digest
    store = tmp_path / "methods"
    dispatcher = _dispatcher(catalog, method_store=store)
    request = _captured_query()
    assert dispatcher.handle(_call(TOOL_NAME, request))["result"]["structuredContent"]["decision"] == "abstain"
    capture = dispatcher.handle(_call(REGISTER_METHOD_TOOL_NAME, _method()))["result"]["structuredContent"]
    folder = store / capture["methodRef"].split(":", 1)[1]
    original_files = {path.name: path.read_bytes() for path in folder.iterdir()}

    decision = dispatcher.handle(_call(TOOL_NAME, request))["result"]["structuredContent"]
    assert decision["decision"] == "instantiate"
    assert decision["selected"]["offer"]["files"] is None
    projection = decision["selected"]["offer"]["method"]
    canonical = _method()["method"]
    for step, delivered in zip(canonical["steps"], projection["steps"], strict=True):
        assert step["instruction"] in delivered and step["expected"] in delivered and step["check"] in delivered
    assert all(item in projection["verification"] for item in canonical["evaluation"])
    assert all(any(item in text for text in projection["verification"]) for item in canonical["constraints"])
    assert all(any(item in text for text in projection["verification"]) for item in canonical["limitations"])
    assert _method()["observedOutcome"] not in json.dumps(decision)
    assert original_files == {path.name: path.read_bytes() for path in folder.iterdir()}
    assert catalog.catalog_digest == original_digest
    assert LocalCatalog(CATALOG).catalog_digest == original_digest
    # A new process/catalog instance can use an original-format capture without migration.
    assert query_with_captured_methods(LocalCatalog(CATALOG), request, store) == decision
    combined = catalog.with_method_capsules(captured_method_capsules(store))
    combined.validate_decision(decision, request=request)
    with pytest.raises(CatalogError, match="no on-disk capsule root"):
        combined.selected_capsule_root(decision)


@pytest.mark.parametrize("mismatch", ["public-scope", "wrong-platform", "unrelated-objective"])
def test_private_capture_keeps_scope_platform_and_relevance_checks(tmp_path: Path, mismatch: str) -> None:
    store = tmp_path / "methods"
    register_method(store, _method())
    request = _captured_query()
    if mismatch == "public-scope":
        request["tenantScope"] = "public"
    elif mismatch == "wrong-platform":
        request["receiver"]["constraints"] = ["windows"]
    else:
        request["objective"] = "Change screen brightness"
    decision = query_with_captured_methods(LocalCatalog(CATALOG), request, store)
    assert decision["decision"] == "abstain" and decision["selected"] is None


def test_portable_capture_does_not_require_a_distribution_tag(tmp_path: Path) -> None:
    method = _method()
    method["platform"] = "any"
    store = tmp_path / "methods"
    register_method(store, method)
    request = _captured_query()
    request["receiver"]["constraints"] = []
    assert query_with_captured_methods(LocalCatalog(CATALOG), request, store)["decision"] == "instantiate"


@pytest.mark.parametrize("tamper", ["capture", "method", "symlink"])
def test_query_rejects_changed_capture_or_method_bytes(tmp_path: Path, tamper: str) -> None:
    store = tmp_path / "methods"
    capture = register_method(store, _method())
    folder = store / capture["methodRef"].split(":", 1)[1]
    if tamper == "capture":
        record = load_json(folder / "capture.json")
        record["observedOutcome"] = "A different outcome"
        (folder / "capture.json").write_bytes(canonical_json_bytes(record) + b"\n")
    elif tamper == "method":
        (folder / "method.json").write_text(json.dumps(_method()["method"], indent=2))
    else:
        (folder / "method.json").unlink()
        (folder / "method.json").symlink_to(ROOT / "examples/publication/method.json")
    dispatcher = _dispatcher(LocalCatalog(CATALOG), method_store=store)
    response = dispatcher.handle(_call(TOOL_NAME, _captured_query()))
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"] == LocalCatalog(CATALOG).query(_captured_query())
    with pytest.raises(MethodCaptureError):
        captured_method_capsules(store)
    request = _captured_query()
    match, complete = CapturedMethodCatalog(LocalCatalog(CATALOG), store).query_objective(
        request["objective"],
        receiver=request["receiver"],
        requested_uses=(request["requestedUse"],),
        tenant_scopes=(request["tenantScope"],),
        evaluated_at=request["evaluatedAt"],
    )
    assert match is None and not complete


def test_query_does_not_wait_on_a_registration_writer(tmp_path: Path) -> None:
    import fcntl

    store = tmp_path / "methods"
    register_method(store, _method())
    with (store / ".register.lock").open("rb") as writer:
        fcntl.flock(writer, fcntl.LOCK_EX)
        with pytest.raises(MethodCaptureError, match="cannot be queried safely"):
            captured_method_capsules(store)


def test_missing_and_empty_capture_stores_do_not_change_legacy_queries(tmp_path: Path) -> None:
    catalog = LocalCatalog(CATALOG)
    request = load_json(ROOT / "examples/requests/exact-python.json")
    store = tmp_path / "methods"
    assert query_with_captured_methods(catalog, request, store) == catalog.query(request)
    assert not store.exists()
    store.mkdir(mode=0o700)
    assert query_with_captured_methods(catalog, request, store) == catalog.query(request)
    assert list(store.iterdir()) == []


def test_existing_exact_decision_keeps_its_original_catalog_binding(tmp_path: Path) -> None:
    catalog = LocalCatalog(CATALOG)
    request = load_json(ROOT / "examples/requests/exact-python.json")
    store = tmp_path / "methods"
    capture = register_method(store, _method())
    original = catalog.query(request)
    result = query_with_captured_methods(catalog, request, store)
    assert canonical_json_bytes(result) == canonical_json_bytes(original)
    catalog.validate_decision(result, request=request)
    assert catalog.selected_capsule_root(result) == catalog.selected_capsule_root(original)
    # Optional new capture failure cannot disable an existing valid catalog hit.
    (store / capture["methodRef"].split(":", 1)[1] / "method.json").write_text("altered")
    assert query_with_captured_methods(catalog, request, store) == original


def test_warm_snapshot_refreshes_after_capture_and_detects_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from limitless_library import method_capture

    store = tmp_path / "methods"
    capture = register_method(store, _method())
    snapshot = CapturedMethodCatalog(LocalCatalog(CATALOG), store)
    original_loader = method_capture.captured_method_capsules
    loads = []

    def counted(path: Path) -> list:
        loads.append(path)
        return original_loader(path)

    monkeypatch.setattr(method_capture, "captured_method_capsules", counted)
    first = snapshot.query(_captured_query())
    assert snapshot.query(_captured_query()) == first
    assert len(loads) == 1
    second_observation = _method()
    second_observation["observedOutcome"] = "The receiver observed the work again."
    register_method(store, second_observation)
    assert snapshot.query(_captured_query())["decision"] == "instantiate"
    assert len(loads) == 2
    assert len(captured_method_capsules(store)) == 1
    method_file = store / capture["methodRef"].split(":", 1)[1] / "method.json"
    stamp = method_file.stat()
    data = method_file.read_bytes()
    method_file.write_bytes(data.replace(b"receiver", b"Receiver", 1))
    os.utime(method_file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert snapshot.query(_captured_query())["decision"] == "abstain"
    with pytest.raises(MethodCaptureError, match="digest-bound"):
        captured_method_capsules(store)
