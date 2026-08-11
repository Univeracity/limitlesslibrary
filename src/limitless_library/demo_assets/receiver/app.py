"""Receiver code that deliberately invokes the installed exact component."""

from _vendor import structured_redaction


def prepare_audit_event(event: dict[str, object]) -> dict[str, object]:
    """Sanitize an agent event before it leaves the local trust boundary."""

    return structured_redaction.redact_event(event)
