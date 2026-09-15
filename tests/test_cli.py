from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from limitless_library import cli
from limitless_library.contracts import load_json
from limitless_library.service_contracts import build_service_query, validate_service_query


class _Profile:
    service_id = "service:example"

    def public_summary(self) -> dict[str, object]:
        return {
            "apiBaseUrl": "https://api.example",
            "defaultAudience": "private",
            "historyMode": "local-only",
        }


class _Connector:
    profile = _Profile()

    def inspect(self) -> object:
        return type(
            "Verified",
            (),
            {
                "discovery": {
                    "dataUsePolicy": {
                        "url": "https://example.test/policy",
                        "digest": "sha256:" + "1" * 64,
                    },
                    "publicationPolicy": {
                        "url": "https://example.test/publication-policy",
                        "revision": "publication-2026-08",
                        "digest": "sha256:" + "2" * 64,
                    },
                    "resultVersions": ["limitless.service-query-result/1.1"],
                    "expiresAt": "2026-08-21T00:00:00Z",
                }
            },
        )()

    def query(self, request: dict[str, object]) -> dict[str, object]:
        return {"verifiedRequest": request}

    def fetch_selected_artifact(
        self,
        *,
        query: dict[str, object],
        result: dict[str, object],
        destination: Path,
    ) -> dict[str, object]:
        assert result == {"verifiedRequest": query}
        destination.write_bytes(b"artifact")
        return {
            "schemaVersion": "limitless.staged-service-artifact/1.0",
            "path": str(destination),
        }


def test_doctor_prints_readiness(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["limitless", "doctor"])
    monkeypatch.setattr(
        cli,
        "containment_readiness",
        lambda: {
            "status": "ready",
            "platform": "linux",
            "pythonVersion": "3.11.0",
            "checks": {
                "linuxHost": True,
                "posixResourceLimits": True,
                "bubblewrapExecutable": True,
                "bubblewrapProbe": True,
            },
            "reason": None,
            "remediation": None,
        },
    )

    cli.main()

    output = capsys.readouterr().out
    assert "Limitless local readiness" in output
    assert "READY: exact adoption can run" in output


def test_doctor_exits_nonzero_with_actionable_remediation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["limitless", "doctor"])
    monkeypatch.setattr(
        cli,
        "containment_readiness",
        lambda: {
            "status": "blocked",
            "platform": "linux",
            "pythonVersion": "3.11.0",
            "checks": {
                "linuxHost": True,
                "posixResourceLimits": True,
                "bubblewrapExecutable": False,
                "bubblewrapProbe": False,
            },
            "reason": "Bubblewrap is not installed",
            "remediation": "Install Bubblewrap.",
        },
    )

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 1
    assert "Next: Install Bubblewrap." in capsys.readouterr().out


def test_service_inspect_exposes_the_effective_nonsecret_boundary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["limitless", "service-inspect", "--profile", "profile.json"])
    monkeypatch.setattr(cli, "_service_connector", lambda _path: _Connector())

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "connected"
    assert output["profile"]["defaultAudience"] == "private"
    assert output["publicationPolicy"]["digest"] == "sha256:" + "2" * 64


def test_service_publish_binds_the_exact_reviewed_policy_digest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    draft = tmp_path / "publication.json"
    digest = "sha256:" + "2" * 64
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "limitless",
            "service-publish",
            "--draft",
            str(draft),
            "--accept-publication-policy-digest",
            digest,
        ],
    )
    monkeypatch.setattr(cli, "activated_service_connector", lambda: _Connector())
    monkeypatch.setattr(
        cli,
        "installation_publisher_authority",
        lambda *, service_id: ("signer", {"publisherId": "installation:example"}),
    )
    monkeypatch.setattr(
        cli,
        "publish_draft",
        lambda connector, **values: (
            calls.append({"connector": connector, **values}) or {"schemaVersion": "limitless.publication-result/1.0"}
        ),
    )

    cli.main()

    assert calls[0]["accepted_publication_policy_digest"] == digest
    assert calls[0]["draft_path"] == draft
    assert json.loads(capsys.readouterr().out)["schemaVersion"] == "limitless.publication-result/1.0"


def test_service_activation_is_one_action_and_prints_the_effective_boundary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(sys, "argv", ["limitless", "service-activate"])
    monkeypatch.setattr(
        cli,
        "activate_official_service",
        lambda: calls.append("activate") or {"enabled": True},
    )
    monkeypatch.setattr(
        cli,
        "activation_details",
        lambda: {
            "schemaVersion": "limitless.official-service-details/1.0",
            "enabled": True,
            "executionMode": "service",
        },
    )

    cli.main()

    assert calls == ["activate"]
    assert json.loads(capsys.readouterr().out)["executionMode"] == "service"


def test_service_inspect_uses_activated_profile_without_a_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected: list[Path | None] = []
    monkeypatch.setattr(sys, "argv", ["limitless", "service-inspect"])
    monkeypatch.setattr(
        cli,
        "_service_connector",
        lambda path: selected.append(path) or _Connector(),
    )

    cli.main()

    assert selected == [None]
    assert json.loads(capsys.readouterr().out)["status"] == "connected"


def test_service_query_accepts_an_exact_request_and_writes_no_implicit_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "query.json"
    request_path.write_text('{"query":"bounded"}', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "limitless",
            "service-query",
            "--profile",
            "profile.json",
            "--request",
            str(request_path),
        ],
    )
    monkeypatch.setattr(cli, "_service_connector", lambda _path: _Connector())

    cli.main()

    assert json.loads(capsys.readouterr().out) == {"verifiedRequest": {"query": "bounded"}}


def test_service_receiver_error_is_clean_before_connector_activation(monkeypatch, capsys, tmp_path) -> None:
    receiver = tmp_path / "receiver.json"
    receiver.write_text('{"constraints": [], "toolchain": {}}', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["limitless", "service-query", "--request-id", "request:test",
                                     "--objective", "Verify prior work", "--receiver", str(receiver)])
    monkeypatch.setattr(cli, "_service_connector", lambda _path: pytest.fail("invalid receiver reached activation"))
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "receiverContext" in output.err
    assert "examples/receiver-context.json" in output.err
    assert "Traceback" not in output.err


def test_documented_service_receiver_builds_a_valid_query(monkeypatch, capsys) -> None:
    from datetime import UTC, datetime

    receiver = Path(__file__).resolve().parents[1] / "examples" / "receiver-context.json"

    class ExampleConnector(_Connector):
        def build_query(self, **arguments):
            return build_service_query(**arguments, requested_audiences=["public"],
                                       requested_treatments=["source-free-method"], execution_mode="service",
                                       history_mode="local-only", client_name="example", client_version="1.0.0",
                                       issued_at=datetime.now(UTC))

    monkeypatch.setattr(sys, "argv", ["limitless", "service-query", "--request-id", "request:example-001",
                                     "--objective", "Verify prior work", "--receiver", str(receiver)])
    monkeypatch.setattr(cli, "_service_connector", lambda _path: ExampleConnector())
    cli.main()
    query = validate_service_query(json.loads(capsys.readouterr().out)["verifiedRequest"])
    assert query["receiverContext"] == load_json(receiver)


def test_seal_method_is_local_and_refuses_overwrite(monkeypatch, capsys, tmp_path) -> None:
    method = Path(__file__).resolve().parents[1] / "examples" / "publication" / "method.json"
    source = tmp_path / "method.json"
    original = json.dumps(load_json(method), indent=2)
    source.write_text(original, encoding="utf-8")
    output = tmp_path / "sealed.json"
    monkeypatch.setattr(sys, "argv", ["limitless", "seal-method", "--draft", str(source), "--output", str(output)])
    monkeypatch.setattr(cli, "activated_service_connector", lambda: pytest.fail("sealing must remain local"))
    cli.main()
    assert json.loads(capsys.readouterr().out)["status"] == "sealed"
    assert load_json(output) == load_json(source)
    assert source.read_text(encoding="utf-8") == original
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert "cannot seal" in capsys.readouterr().err


def test_agent_connect_uses_the_general_antigravity_adapter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog"
    calls: list[Path] = []
    monkeypatch.setattr(sys, "argv", ["limitless", "agent-connect", "antigravity", "--catalog", str(catalog)])
    monkeypatch.setattr(
        cli,
        "connect_antigravity",
        lambda selected: calls.append(selected) or {"status": "connected", "agent": "antigravity"},
    )

    cli.main()

    assert calls == [catalog]
    assert json.loads(capsys.readouterr().out) == {"agent": "antigravity", "status": "connected"}


def test_agent_status_and_disconnect_use_the_general_antigravity_adapter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["limitless", "agent-status", "agy"])
    monkeypatch.setattr(cli, "antigravity_connection_status", lambda: {"status": "connected"})

    cli.main()

    assert json.loads(capsys.readouterr().out) == {"status": "connected"}
    monkeypatch.setattr(sys, "argv", ["limitless", "agent-disconnect", "antigravity"])
    monkeypatch.setattr(cli, "disconnect_antigravity", lambda: {"status": "disconnected"})

    cli.main()

    assert json.loads(capsys.readouterr().out) == {"status": "disconnected"}


def test_service_query_can_stage_an_exact_artifact_without_printing_the_raw_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "query.json"
    artifact_path = tmp_path / "selected.bin"
    request_path.write_text('{"query":"bounded"}', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "limitless",
            "service-query",
            "--request",
            str(request_path),
            "--artifact-output",
            str(artifact_path),
        ],
    )
    monkeypatch.setattr(cli, "_service_connector", lambda _path: _Connector())

    cli.main()

    assert artifact_path.read_bytes() == b"artifact"
    output = json.loads(capsys.readouterr().out)
    assert output["schemaVersion"] == "limitless.staged-service-artifact/1.0"
    assert output["path"] == str(artifact_path)
