from __future__ import annotations

import sys

import pytest

from limitless_library import cli


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
