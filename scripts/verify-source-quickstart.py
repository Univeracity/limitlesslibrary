#!/usr/bin/env python3
"""Verify the advertised one-command source-checkout experience in isolation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FIRST_USE_BUDGET_SECONDS = 5 * 60


class SourceQuickstartError(RuntimeError):
    """The clean source-checkout path was not usable."""


def _copy_source(destination: Path) -> Path:
    checkout = destination / "limitlesslibrary"
    checkout.mkdir()
    for name in ("LICENSE", "NOTICE", "README.md", "pyproject.toml"):
        shutil.copy2(ROOT / name, checkout / name)
    shutil.copytree(ROOT / "src", checkout / "src")
    (checkout / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts" / "limitless", checkout / "scripts" / "limitless")
    return checkout


def _run(checkout: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return subprocess.run(
        [sys.executable, "-I", str(checkout / "scripts" / "limitless"), *arguments],
        cwd=checkout,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=FIRST_USE_BUDGET_SECONDS,
    )


def _json(checkout: Path, *arguments: str) -> dict[str, Any]:
    completed = _run(checkout, *arguments)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SourceQuickstartError("the source launcher did not return JSON") from error
    if not isinstance(value, dict):
        raise SourceQuickstartError("the source launcher JSON must be an object")
    return value


def main() -> int:
    started = perf_counter()
    with tempfile.TemporaryDirectory(prefix="limitless-source-first-use-") as temporary:
        checkout = _copy_source(Path(temporary))

        quickstart = _run(checkout)
        first_use_seconds = perf_counter() - started
        evidence = checkout / ".limitless" / "quickstart"
        expected = {
            "exact-decision.json",
            "method-decision.json",
            "abstention-decision.json",
            "adoption-receipt.json",
        }
        if "Limitless local verified-reuse lifecycle" not in quickstart.stdout:
            raise SourceQuickstartError("the default command did not run the complete lifecycle")
        if not evidence.is_dir() or not expected.issubset({item.name for item in evidence.iterdir()}):
            raise SourceQuickstartError("the default command did not retain inspectable evidence")

        doctor = _json(checkout, "doctor", "--format", "json")
        if doctor.get("status") != "ready" or not all(doctor.get("checks", {}).values()):
            raise SourceQuickstartError("the readiness diagnostic did not prove containment")

        replay = _json(checkout, "demo", "--format", "json")
        exact = replay.get("exact")
        if (
            not isinstance(exact, dict)
            or exact.get("technicalIntegrationVerified") is not True
            or exact.get("runtimeAdherenceVerified") is not True
            or replay.get("method", {}).get("treatment") != "method-guided"
            or replay.get("abstention", {}).get("decision") != "abstain"
        ):
            raise SourceQuickstartError("the isolated replay did not prove all three safe outcomes")
        if first_use_seconds > FIRST_USE_BUDGET_SECONDS:
            raise SourceQuickstartError("the clean first use exceeded five minutes")

    print(
        json.dumps(
            {
                "schemaVersion": "limitless.source-first-use.v1",
                "status": "passed",
                "firstUseSeconds": round(first_use_seconds, 3),
                "budgetSeconds": FIRST_USE_BUDGET_SECONDS,
                "manualEnvironmentSetupRequired": False,
                "evidenceRetained": True,
                "containmentProbed": True,
                "exactAdoptionVerified": True,
                "methodGuidanceVerified": True,
                "abstentionVerified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
