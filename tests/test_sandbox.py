from __future__ import annotations

import os
from pathlib import Path

import pytest
from limitless_library import sandbox


def _fake_python(prefix: Path) -> Path:
    executable = prefix / "bin" / "python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"host-controlled test runtime\n")
    executable.chmod(0o755)
    return executable


def test_hosted_python_prefix_is_mounted_read_only_at_fixed_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "hostedtoolcache" / "Python" / "3.12" / "x64"
    executable = _fake_python(prefix)
    monkeypatch.setattr(sandbox.sys, "executable", str(executable))
    monkeypatch.setattr(sandbox.sys, "prefix", str(prefix))
    monkeypatch.setattr(sandbox.sys, "base_prefix", str(prefix))

    assert sandbox.contained_python() == "/runtime/bin/python"
    binds = sandbox._runtime_binds()
    assert binds[-3:] == ["--ro-bind", str(prefix), "/runtime"]
    assert sandbox._runtime_environment() == [
        "--setenv",
        "LD_LIBRARY_PATH",
        "/runtime/lib:/runtime/lib64",
    ]


def test_broad_python_prefix_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable = _fake_python(tmp_path / "runtime")
    monkeypatch.setattr(sandbox.sys, "executable", str(executable))
    monkeypatch.setattr(sandbox.sys, "prefix", os.sep)
    monkeypatch.setattr(sandbox.sys, "base_prefix", os.sep)

    with pytest.raises(sandbox.SandboxError, match="outside the contained runtime mounts"):
        sandbox.contained_python()


def test_containment_readiness_explains_missing_bubblewrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    original_which = sandbox.shutil.which
    monkeypatch.setattr(sandbox.shutil, "which", lambda command: None if command == "bwrap" else original_which(command))

    result = sandbox.containment_readiness()

    assert result["status"] == "blocked"
    assert result["checks"]["bubblewrapExecutable"] is False
    assert result["checks"]["bubblewrapProbe"] is False
    assert "not installed" in result["reason"]


def test_containment_readiness_requires_a_successful_namespace_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(sandbox, "_run_bounded", lambda *args, **kwargs: (1, b"", b"blocked"))

    result = sandbox.containment_readiness()

    assert result["status"] == "blocked"
    assert result["checks"]["bubblewrapExecutable"] is True
    assert result["checks"]["bubblewrapProbe"] is False
    assert "namespaces" in result["reason"]


def test_containment_readiness_reports_a_usable_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(sandbox, "_run_bounded", lambda *args, **kwargs: (0, b"", b""))

    result = sandbox.containment_readiness()

    assert result["status"] == "ready"
    assert all(result["checks"].values())
