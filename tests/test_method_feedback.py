from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from limitless_library.catalog import LocalCatalog
from limitless_library.contracts import load_json
from limitless_library.method_capture import CapturedMethodCatalog, register_method
from limitless_library.method_feedback import MethodFeedbackError, record_method_feedback
from limitless_library.objective_query import ObjectiveQueryEngine

ROOT = Path(__file__).parents[1]


def selected(root: Path):
    store = root / "methods"
    register_method(
        store,
        {
            "title": "Observed receiver adoption",
            "taskKind": "receiver-verification",
            "method": load_json(ROOT / "examples/publication/method.json"),
            "observedOutcome": "The receiver observed the result.",
            "platform": "any",
        },
    )
    engine = ObjectiveQueryEngine(
        CapturedMethodCatalog(LocalCatalog.empty(root), store), policy_path=None, state_dir=root / "queries"
    )
    view = engine.check({"objective": "Observed receiver adoption"})
    return view


def test_private_failure_is_bound_idempotent_and_cannot_attest_or_publish(tmp_path: Path) -> None:
    view = selected(tmp_path)
    original = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*.json")}
    arguments = {
        "queryRef": view["queryRef"],
        "status": "failed",
        "reasonCode": "check-failed",
        "note": "Receiver test did not pass.",
    }
    first = record_method_feedback(tmp_path / "queries", arguments)
    assert first["assurance"] == "self-reported" and first["destination"] == "private"
    feedback = next((tmp_path / "method-feedback").glob("*.json"))
    record = json.loads(feedback.read_text())
    assert record["identity"]["binding"]["selection"]["contentDigest"] == view["selection"]["digest"]
    assert record["identity"]["binding"]["receiverDigest"] == view["receiverDigest"]
    before = feedback.read_bytes()
    assert record_method_feedback(tmp_path / "queries", arguments) == {**first, "status": "duplicate"}
    assert feedback.read_bytes() == before and feedback.stat().st_mode & 0o077 == 0
    assert all((tmp_path / name).read_bytes() == data for name, data in original.items())
    assert not list(tmp_path.rglob("publication.json"))


@pytest.mark.parametrize(
    "override", [{"assurance": "verified"}, {"destination": "public"}, {"queryRef": "query:" + "0" * 32}]
)
def test_model_cannot_forge_assurance_scope_or_unbound_reference(tmp_path: Path, override: dict) -> None:
    view = selected(tmp_path)
    arguments = {
        "queryRef": view["queryRef"],
        "status": "succeeded",
        "reasonCode": "checks-passed",
        "note": "",
        **override,
    }
    with pytest.raises(MethodFeedbackError):
        record_method_feedback(tmp_path / "queries", arguments)
    assert not (tmp_path / "method-feedback").exists()


def test_tampered_continuation_and_abstention_cannot_become_success(tmp_path: Path) -> None:
    view = selected(tmp_path)
    query = next((tmp_path / "queries").glob("query-*.json"))
    record = json.loads(query.read_text())
    record["payload"]["objective"] = "Different work"
    query.write_text(json.dumps(record))
    with pytest.raises(MethodFeedbackError):
        record_method_feedback(
            tmp_path / "queries",
            {"queryRef": view["queryRef"], "status": "succeeded", "reasonCode": "checks-passed", "note": ""},
        )

    empty = ObjectiveQueryEngine(
        CapturedMethodCatalog(LocalCatalog.empty(tmp_path), None), policy_path=None, state_dir=tmp_path / "queries"
    )
    abstention = empty.check({"objective": "Unrelated work"})
    with pytest.raises(MethodFeedbackError):
        record_method_feedback(
            tmp_path / "queries",
            {"queryRef": abstention["queryRef"], "status": "succeeded", "reasonCode": "checks-passed", "note": ""},
        )


def test_contradictory_outcome_and_tampered_existing_feedback_are_rejected(tmp_path: Path) -> None:
    view = selected(tmp_path)
    arguments = {"queryRef": view["queryRef"], "status": "failed", "reasonCode": "checks-passed", "note": ""}
    with pytest.raises(MethodFeedbackError):
        record_method_feedback(tmp_path / "queries", arguments)
    arguments["reasonCode"] = "check-failed"
    record_method_feedback(tmp_path / "queries", arguments)
    path = next((tmp_path / "method-feedback").glob("*.json"))
    record = json.loads(path.read_text())
    record["identity"]["status"] = "succeeded"
    path.write_text(json.dumps(record))
    with pytest.raises(MethodFeedbackError, match="changed"):
        record_method_feedback(tmp_path / "queries", arguments)


def test_real_stdio_check_then_outcome_with_private_continuation(tmp_path: Path) -> None:
    view = selected(tmp_path)
    from limitless_library.mcp_protocol import modern_metadata

    args = {
        "queryRef": view["queryRef"],
        "status": "blocked",
        "reasonCode": "missing-capability",
        "note": "Receiver cannot perform this check.",
    }
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "limitless_record_outcome",
            "arguments": args,
            "_meta": modern_metadata(client_name="feedback-test", client_version="1"),
        },
    }
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TMPDIR") if key in os.environ}
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "limitless_library.mcp_server",
            "--method-store",
            str(tmp_path / "methods"),
            "--query-state",
            str(tmp_path / "queries"),
        ],
        input=json.dumps(call) + "\n",
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    result = json.loads(completed.stdout)["result"]
    assert result["isError"] is False and result["structuredContent"]["assurance"] == "self-reported"
    assert result["structuredContent"]["destination"] == "private"
