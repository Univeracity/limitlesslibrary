"""Receiver-owned functional and adversarial obligations."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    sys.path.insert(0, str(Path("/work")))
    import app

    checks = []
    if app.render(" Grace ") != "Hello, Grace!":
        raise SystemExit("normalization behavior differs")
    checks.append("normalization")
    for invalid in ("", "   ", None):
        try:
            app.render(invalid)
        except ValueError:
            continue
        raise SystemExit("invalid name was accepted")
    checks.append("invalid-inputs")
    print(
        json.dumps(
            {
                "schemaVersion": "limitless.verifier-result/0.1",
                "verifierId": "receiver-obligations",
                "kind": "obligation",
                "passed": True,
                "checks": checks,
                "assetDigest": None,
                "immutableBytes": None,
                "runtimeInvoked": None,
                "invocationCount": None,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
