from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from limitless_library.catalog import LocalCatalog
from limitless_library.contracts import load_json
from limitless_library.mcp_protocol import modern_metadata
from limitless_library.mcp_server import REGISTER_METHOD_TOOL_NAME, TOOL_NAME, _dispatcher
from limitless_library.method_capture import MethodCaptureError, register_method, sync_methods
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
    assert [tool["name"] for tool in responses[0]["result"]["tools"]] == [TOOL_NAME, REGISTER_METHOD_TOOL_NAME]
    assert responses[1]["result"]["structuredContent"]["destination"] == "local"
