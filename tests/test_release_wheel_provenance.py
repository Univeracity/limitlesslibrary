from __future__ import annotations

import importlib.util
import subprocess
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "reproduce-release-wheel.py"
spec = importlib.util.spec_from_file_location("release_wheel_provenance", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_wheel(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)


def test_compares_python_and_package_resources(tmp_path: Path) -> None:
    files = {"limitless_library/cli.py": b"pass\n", "limitless_library/schemas/capsule.json": b"{}"}
    wheel = tmp_path / "core.whl"
    write_wheel(wheel, {**files, "core.dist-info/METADATA": b"Name: core\n"})
    result = module.compare_package(wheel, files)
    assert [row["path"] for row in result] == sorted(files)


@pytest.mark.parametrize("change", ["modified-python", "modified-resource", "added", "missing"])
def test_rejects_changed_or_incomplete_package(tmp_path: Path, change: str) -> None:
    source = {"limitless_library/cli.py": b"pass\n", "limitless_library/config.json": b"{}"}
    delivered = dict(source)
    if change == "modified-python":
        delivered["limitless_library/cli.py"] = b"raise RuntimeError\n"
    elif change == "modified-resource":
        delivered["limitless_library/config.json"] = b'{"changed": true}'
    elif change == "added":
        delivered["limitless_library/extra.py"] = b"pass\n"
    else:
        del delivered["limitless_library/config.json"]
    wheel = tmp_path / "core.whl"
    write_wheel(wheel, delivered)
    with pytest.raises(ValueError, match="wheel package file"):
        module.compare_package(wheel, source)


def test_rejects_duplicate_wheel_members(tmp_path: Path) -> None:
    wheel = tmp_path / "core.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("limitless_library/cli.py", b"pass\n")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("limitless_library/cli.py", b"pass\n")
    with pytest.raises(ValueError, match="duplicate"):
        module.compare_package(wheel, {"limitless_library/cli.py": b"pass\n"})


def test_requires_the_exact_source_commit(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "fixture",
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="checkout does not match"):
        module.source_archive(tmp_path, {"commit": "0" * 40, "sourceDateEpoch": 0})
