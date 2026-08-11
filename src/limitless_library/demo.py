"""One-command, local demonstration of the verified-reuse lifecycle."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from .catalog import LocalCatalog
from .contracts import load_json, write_new_json
from .installer import adopt_exact_component


class DemoError(RuntimeError):
    """The bundled demonstration could not run safely."""


def _assets() -> Path:
    root = Path(__file__).with_name("demo_assets")
    if not root.is_dir():
        raise DemoError("bundled demo assets are unavailable")
    return root


def _load_component(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("limitless_demo_structured_redaction", path)
    if spec is None or spec.loader is None:
        raise DemoError("cannot load the installed demo component")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _execute(workspace: Path, *, retained: bool) -> dict[str, Any]:
    assets = _assets()
    catalog = LocalCatalog(assets / "catalog")
    receiver = workspace / "receiver"
    shutil.copytree(assets / "receiver", receiver)

    exact = catalog.query(load_json(assets / "requests" / "exact-python.json"))
    exact_path = workspace / "exact-decision.json"
    write_new_json(exact_path, exact)
    receipt_path = workspace / "adoption-receipt.json"
    receipt = adopt_exact_component(
        catalog,
        exact,
        load_json(receiver / "recipe.json"),
        receiver,
        owner_authorized=True,
        receipt_path=receipt_path,
    )

    component_path = receiver / "_vendor" / "structured_redaction.py"
    component = _load_component(component_path)
    sample_value = "demo-only-value"
    sample_input = {
        "agent": "release-agent",
        "action": "deploy",
        "authorization": sample_value,
        "metadata": {"repository": "acme/api", "token": sample_value},
    }
    sample_output = component.redact_event(sample_input)

    method = catalog.query(load_json(assets / "requests" / "method-portable.json"))
    abstention = catalog.query(load_json(assets / "requests" / "abstain.json"))
    write_new_json(workspace / "method-decision.json", method)
    write_new_json(workspace / "abstention-decision.json", abstention)

    return {
        "status": "complete",
        "catalogDigest": catalog.catalog_digest,
        "exact": {
            "decision": exact["decision"],
            "treatment": exact["treatment"],
            "offerId": exact["selected"]["offer"]["id"],
            "installedTarget": receipt["installedFiles"][0]["target"],
            "technicalIntegrationVerified": receipt["disposition"]["technicalIntegrationVerified"],
            "runtimeAdherenceVerified": receipt["disposition"]["runtimeAdherenceVerified"],
            "verifiers": [item["id"] for item in receipt["verifierResults"]],
            "receiptDigest": receipt["receiptDigest"],
        },
        "usefulResult": {"input": sample_input, "output": sample_output},
        "method": {
            "decision": method["decision"],
            "treatment": method["treatment"],
            "summary": method["selected"]["offer"]["method"]["summary"],
            "sourceFilesDisclosed": method["selected"]["offer"]["files"] is not None,
        },
        "abstention": {
            "decision": abstention["decision"],
            "reason": abstention["reason"],
            "candidateDetailsDisclosed": abstention["selected"] is not None,
        },
        "artifacts": {
            "retained": retained,
            "workspace": str(workspace) if retained else None,
            "files": [
                "exact-decision.json",
                "method-decision.json",
                "abstention-decision.json",
                "adoption-receipt.json",
                "receiver/_vendor/structured_redaction.py",
            ],
        },
    }


def run_demo(workspace: Path | None = None) -> dict[str, Any]:
    """Run exact adoption, method selection, and abstention entirely locally."""

    if workspace is not None:
        destination = Path(workspace).resolve()
        if destination.exists() or destination.is_symlink():
            raise DemoError(f"refusing to overwrite demo workspace: {destination}")
        try:
            destination.mkdir(parents=True)
        except OSError as error:
            raise DemoError(f"cannot create demo workspace: {destination}") from error
        return _execute(destination, retained=True)

    with tempfile.TemporaryDirectory(prefix="limitless-demo-") as temporary:
        return _execute(Path(temporary), retained=False)


def format_demo(result: dict[str, Any]) -> str:
    """Render the lifecycle result for a terminal or short product demo."""

    exact = result["exact"]
    method = result["method"]
    abstention = result["abstention"]
    artifacts = result["artifacts"]
    lines = [
        "Limitless local verified-reuse lifecycle",
        "",
        "EXACT COMPONENT",
        f"  decision: {exact['decision']} / {exact['treatment']}",
        f"  installed: {exact['installedTarget']} (exact bytes, no overwrite)",
        "  verified: receiver obligations + observed runtime invocation",
        f"  receipt: {exact['receiptDigest']}",
        "",
        "USEFUL LOCAL RESULT",
        f"  {json.dumps(result['usefulResult']['output'], sort_keys=True)}",
        "",
        "SOURCE-FREE METHOD",
        f"  decision: {method['decision']} / {method['treatment']}",
        f"  guidance: {method['summary']}",
        "",
        "NO SAFE MATCH",
        f"  decision: {abstention['decision']} (candidate details withheld)",
        "",
    ]
    if artifacts["retained"]:
        lines.append(f"Evidence retained at {artifacts['workspace']}")
    else:
        lines.append("Run with --workspace PATH to retain decisions, installed bytes, and the receipt.")
    return "\n".join(lines)
