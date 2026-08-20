from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from limitless_library import cli


class _Profile:
    def public_summary(self) -> dict[str, object]:
        return {"apiBaseUrl": "https://api.example", "dataUseMode": "confidential"}


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
    assert output["profile"]["dataUseMode"] == "confidential"


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
