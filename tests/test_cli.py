from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from limitless_library import cli


class _Profile:
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
                    "resultVersions": ["limitless.service-query-result/1.1"],
                    "expiresAt": "2026-08-21T00:00:00Z",
                }
            },
        )()

    def query(self, request: dict[str, object]) -> dict[str, object]:
        return {"verifiedRequest": request}


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
