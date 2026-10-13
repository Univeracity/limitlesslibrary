#!/usr/bin/env python3
"""Rebuild an exact public release wheel twice and record its source correspondence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *arguments])


def source_archive(root: Path, source: dict[str, object]) -> tuple[bytes, str]:
    commit = source["commit"]
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full Git SHA")
    if git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("source checkout does not match the declared commit")
    epoch = int(git(root, "show", "-s", "--format=%ct", commit))
    if epoch != source["sourceDateEpoch"]:
        raise ValueError("SOURCE_DATE_EPOCH does not match the source commit timestamp")
    return git(root, "archive", commit), git(root, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def compare_package(wheel_path: Path, source_files: dict[str, bytes]) -> list[dict[str, str]]:
    """Compare every delivered package file, including JSON resources and py.typed."""
    with zipfile.ZipFile(wheel_path) as wheel:
        names = wheel.namelist()
        if len(names) != len(set(names)):
            raise ValueError("wheel contains duplicate member paths")
        delivered = {name: wheel.read(name) for name in names if name.startswith("limitless_library/")}
        if delivered.keys() != source_files.keys():
            raise ValueError("wheel package file set does not match the source archive")
        for name, expected in source_files.items():
            if delivered[name] != expected:
                raise ValueError(f"wheel package file differs from source: {name}")
    return [{"path": name, "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(delivered.items())]


def reproduce(source_root: Path, recipe_path: Path, output: Path) -> dict[str, object]:
    recipe = json.loads(recipe_path.read_text())
    if recipe["schemaVersion"] != "limitless.release-wheel-build/1":
        raise ValueError("unsupported build recipe")
    wheel_name = recipe["wheel"]["name"]
    expected_digest = recipe["wheel"]["sha256"]
    if Path(wheel_name).name != wheel_name or not wheel_name.endswith(".whl"):
        raise ValueError("wheel name must be a plain wheel filename")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ValueError("wheel SHA256 must be a full digest")
    tools = recipe["tools"]
    if platform.python_version() != tools["python"]:
        raise ValueError("Python version does not match the build recipe")
    for name, version in tools.items():
        if name != "python" and importlib.metadata.version(name) != version:
            raise ValueError(f"build tool does not match the recipe: {name}=={version}")
    archive, tree = source_archive(source_root, recipe["source"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source_files = {
            member.name.removeprefix("src/"): source.extractfile(member).read()
            for member in source.getmembers()
            if member.isfile() and member.name.startswith("src/limitless_library/")
        }
    if not source_files:
        raise ValueError("source archive contains no core package files")
    output.mkdir(parents=True, exist_ok=True)
    results = []
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(recipe["source"]["sourceDateEpoch"])}
    with tempfile.TemporaryDirectory(prefix="release-rebuild-", dir=output) as temporary:
        for copy in ("a", "b"):
            root = Path(temporary) / copy
            root.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                source.extractall(root, filter="data")
            dist = root / "wheel-output"
            subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist)],
                cwd=root,
                env=env,
                check=True,
            )
            wheels = list(dist.glob("*.whl"))
            if len(wheels) != 1 or wheels[0].name != wheel_name:
                raise ValueError("build did not produce the declared wheel")
            observed_digest = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
            if observed_digest != expected_digest:
                raise ValueError(f"rebuilt wheel digest differs from the shipped release: {observed_digest}")
            package_files = compare_package(wheels[0], source_files)
            results.append({"copy": copy, "sha256": observed_digest})
            if copy == "a":
                shutil.copyfile(wheels[0], output / wheel_name)
    run_id = os.environ.get("GITHUB_RUN_ID")
    repository = os.environ.get("GITHUB_REPOSITORY")
    report = {
        "schemaVersion": "limitless.release-wheel-proof/1",
        "source": {**recipe["source"], "tree": tree, "archiveSha256": hashlib.sha256(archive).hexdigest()},
        "wheel": recipe["wheel"],
        "tools": {**tools, "pythonFullVersion": platform.python_version()},
        "builds": results,
        "packageFiles": package_files,
        "comparison": "Both clean source-archive builds match the complete shipped wheel SHA256; all package files match source.",
        "builder": {
            "repository": repository,
            "commit": os.environ.get("GITHUB_SHA"),
            "runUrl": f"https://github.com/{repository}/actions/runs/{run_id}" if run_id and repository else None,
            "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
    }
    (output / "wheel-build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = reproduce(arguments.source_root.resolve(), arguments.recipe, arguments.output.resolve())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"release wheel reproduction failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"source": report["source"], "wheel": report["wheel"], "builds": report["builds"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
