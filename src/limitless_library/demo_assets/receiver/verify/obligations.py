"""Receiver-owned functional and adversarial obligations."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    sys.path.insert(0, str(Path("/work")))
    import app

    sample_value = "demo-only-value"
    original = {
        "agent": "release-agent",
        "authorization": sample_value,
        "metadata": {"repository": "acme/api", "token": sample_value, "attempt": 2},
        "steps": [{"name": "build", "api_key": sample_value}],
    }
    result = app.prepare_audit_event(original)
    if result["agent"] != "release-agent" or result["metadata"]["repository"] != "acme/api":
        raise SystemExit("non-sensitive fields changed")
    if result["authorization"] != "[REDACTED]" or result["metadata"]["token"] != "[REDACTED]":
        raise SystemExit("nested sensitive fields were not redacted")
    if result["steps"][0]["api_key"] != "[REDACTED]":
        raise SystemExit("sensitive fields inside arrays were not redacted")
    if original["authorization"] != sample_value or original["metadata"]["token"] != sample_value:
        raise SystemExit("input event was mutated")
    try:
        app.prepare_audit_event(["not", "a", "mapping"])
    except TypeError:
        pass
    else:
        raise SystemExit("invalid input was accepted")

    print(
        json.dumps(
            {
                "schemaVersion": "limitless.verifier-result/0.1",
                "verifierId": "receiver-obligations",
                "kind": "obligation",
                "passed": True,
                "checks": ["nested-redaction", "preserve-fields", "no-mutation", "invalid-input"],
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
