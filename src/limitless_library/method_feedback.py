"""Private, immutable reuse observations; model reports never attest success."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes, sha256_json, utc_now, without, write_new_json
from .objective_query import load_query_record
from .query_policy import private_directory, read_private_json
from .schemas import SchemaError, validate

MAX_FEEDBACK_BYTES = 16 * 1024
MAX_FEEDBACK_RECORDS = 2000


class MethodFeedbackError(ValueError):
    """A reuse observation is invalid, unbound, or cannot be stored safely."""


def _selection(payload: dict[str, Any]) -> dict[str, Any]:
    local = payload.get("localMatch")
    service = payload.get("serviceResult")
    if local is not None:
        selected = local["decision"]["selected"]
        return {
            "origin": "local",
            "reference": selected["offer"]["id"],
            "contentDigest": selected["capsule"]["digest"],
            "treatment": "source-free-method" if selected["offer"]["kind"] == "method" else "exact-component",
        }
    if service is not None and service["treatment"] != "abstention":
        selected = service["selection"]
        return {
            "origin": "service",
            "reference": selected["capabilityId"],
            "contentDigest": selected["cardDigest"],
            "treatment": service["treatment"],
        }
    raise MethodFeedbackError("outcome requires a selected, privately bound result")


def record_method_feedback(
    query_state: Path, arguments: dict[str, Any], *, feedback_dir: Path | None = None
) -> dict[str, Any]:
    """Record a self-report only; never publish it or rewrite selection state."""
    try:
        validate(arguments, "method-feedback-input-1.0.schema.json", "method feedback")
        payload = load_query_record(query_state, arguments["queryRef"])
        selection = _selection(payload)
        binding = {
            "selection": selection,
            "receiverDigest": sha256_json({"local": payload["receiver"], "service": payload["serviceReceiver"]}),
        }
    except (SchemaError, OSError, ValueError, KeyError, TypeError) as error:
        raise MethodFeedbackError("outcome cannot be bound to a valid private selection") from error
    identity = {
        "queryRef": arguments["queryRef"],
        "binding": binding,
        "status": arguments["status"],
        "reasonCode": arguments["reasonCode"],
        "note": arguments["note"],
    }
    reference = "feedback:" + sha256_json(identity)[7:]
    root = private_directory(feedback_dir or query_state.parent / "method-feedback")
    import fcntl

    lock = os.open(root / ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise MethodFeedbackError("feedback lock is unsafe")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = root / (reference[9:] + ".json")
        if path.exists():
            previous = read_private_json(path, maximum=MAX_FEEDBACK_BYTES)
            if (
                previous.get("schemaVersion") != "limitless.private-reuse-feedback/1.0"
                or previous.get("feedbackRef") != reference
                or previous.get("assurance") != "self-reported"
                or previous.get("feedbackDigest") != sha256_json(without(previous, "feedbackDigest"))
                or previous.get("identity") != identity
            ):
                raise MethodFeedbackError("stored feedback is changed or misbound")
            status = "duplicate"
        else:
            if len(list(root.glob("*.json"))) >= MAX_FEEDBACK_RECORDS:
                raise MethodFeedbackError("feedback store exceeds its supported bound")
            record = {
                "schemaVersion": "limitless.private-reuse-feedback/1.0",
                "feedbackRef": reference,
                "identity": identity,
                "assurance": "self-reported",
                "recordedAt": utc_now(),
            }
            record["feedbackDigest"] = sha256_json(record)
            if len(canonical_json_bytes(record)) + 1 > MAX_FEEDBACK_BYTES:
                raise MethodFeedbackError("feedback exceeds its byte limit")
            write_new_json(path, record)
            status = "recorded"
    except (OSError, ValueError) as error:
        raise MethodFeedbackError(str(error)) from error
    finally:
        os.close(lock)
    result = {
        "schemaVersion": "limitless.method-feedback-result/1.0",
        "status": status,
        "feedbackRef": reference,
        "assurance": "self-reported",
        "destination": "private",
    }
    validate(result, "method-feedback-result-1.0.schema.json", "feedback result")
    return result
