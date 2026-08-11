"""Receiver-owned proof that runtime code invokes the immutable component."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

EXPECTED_COMPONENT_DIGEST = "sha256:75678859485adb0ec036d28e4e3584b09788724cf5e0d64ceed3da3d94147de2"


def main() -> None:
    receiver = Path("/work")
    component = receiver / "_vendor" / "structured_redaction.py"
    observed = "sha256:" + hashlib.sha256(component.read_bytes()).hexdigest()
    if observed != EXPECTED_COMPONENT_DIGEST:
        raise SystemExit("installed component bytes differ")

    sys.path.insert(0, str(receiver))
    import app

    calls = 0
    original = app.structured_redaction.redact_event

    def probe(event: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original(event)

    app.structured_redaction.redact_event = probe
    sample_value = "demo-only-value"
    result = app.prepare_audit_event({"action": "deploy", "authorization": sample_value})
    if result != {"action": "deploy", "authorization": "[REDACTED]"} or calls != 1:
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
