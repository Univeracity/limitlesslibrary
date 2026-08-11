"""Receiver-owned proof that its runtime invokes the immutable component."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

EXPECTED_COMPONENT_DIGEST = "sha256:3c773ff03e1464fa36f77936d670f7d76f948452831f4518c1ebcc578699f3bb"


def main() -> None:
    receiver = Path("/work")
    component = receiver / "_vendor" / "greeting.py"
    observed = "sha256:" + hashlib.sha256(component.read_bytes()).hexdigest()
    if observed != EXPECTED_COMPONENT_DIGEST:
        raise SystemExit("installed component bytes differ")
    sys.path.insert(0, str(receiver))
    import app

    calls = 0
    original = app.greeting.greeting

    def probe(name: str) -> str:
        nonlocal calls
        calls += 1
        return original(name)

    app.greeting.greeting = probe
    if app.render("Ada") != "Hello, Ada!" or calls != 1:
        raise SystemExit("receiver did not invoke the supplied component")
    print(
        json.dumps(
            {
                "schemaVersion": "limitless.verifier-result/0.1",
                "verifierId": "runtime-adherence",
                "kind": "adherence",
                "passed": True,
                "checks": ["exact-file-digest", "receiver-runtime-invocation"],
                "assetDigest": os.environ["LIMITLESS_ASSET_DIGEST"],
                "immutableBytes": True,
                "runtimeInvoked": True,
                "invocationCount": calls,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
