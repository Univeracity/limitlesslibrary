"""Ownership-aware MCP setup for supported general-purpose agent clients.

The local Library is useful outside any one host integration. This module keeps
agent configuration intentionally narrow: it adds one named stdio server to a
documented client profile, preserves unrelated entries, and writes a local
ownership record. A later disconnect only removes an entry that still matches
the exact descriptor it created.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from tempfile import mkstemp
from typing import Any

from .contracts import strict_json_loads, utc_now


class AgentIntegrationError(ValueError):
    """A local agent integration cannot be safely configured."""


ANTIGRAVITY_AGENT = "antigravity"
AGENT_IDS = (ANTIGRAVITY_AGENT,)
AGENT_MCP_SERVER_NAME = "limitless-library"
SERVER_NAME = AGENT_MCP_SERVER_NAME
_STATE_SCHEMA = "limitless.agent-connection-state/1.0"
_REPORT_SCHEMA = "limitless.agent-connection-report/1.0"


def _home(value: Path | None) -> Path:
    selected = Path(value) if value is not None else Path.home()
    if not selected.is_absolute() or selected.is_symlink() or not selected.is_dir():
        raise AgentIntegrationError("agent home must be an absolute, non-symlink directory")
    return selected


def _state_path(*, home: Path, state_path: Path | None) -> Path:
    if state_path is not None:
        selected = Path(state_path)
        if not selected.is_absolute():
            raise AgentIntegrationError("agent connection state path must be absolute")
        return selected
    configured = os.environ.get("XDG_STATE_HOME")
    root = Path(configured) if configured and Path(configured).is_absolute() else home / ".local" / "state"
    return root / "limitless-library" / "agent-connections.json"


def _antigravity_profile_path(home: Path) -> Path:
    """Choose the documented modern profile, retaining pre-migration support."""

    modern = home / ".gemini" / "config" / "mcp_config.json"
    legacy = home / ".gemini" / "antigravity" / "mcp_config.json"
    if modern.exists() or (modern.parent / ".migrated").exists():
        return modern
    if legacy.exists():
        return legacy
    return modern


def _load_json_object(
    path: Path,
    *,
    absent: dict[str, Any],
    label: str,
    allow_empty: bool = False,
) -> dict[str, Any]:
    if not path.exists():
        return dict(absent)
    if path.is_symlink() or not path.is_file():
        raise AgentIntegrationError(f"{label} is not a regular file")
    try:
        raw = path.read_text(encoding="utf-8")
        if allow_empty and not raw.strip():
            return dict(absent)
        value = strict_json_loads(raw)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AgentIntegrationError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise AgentIntegrationError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, value: dict[str, Any], *, mode: int) -> None:
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise AgentIntegrationError(f"cannot create {path.parent}") from error
    if parent.is_symlink() or not parent.is_dir():
        raise AgentIntegrationError(f"configuration parent is unsafe: {parent}")
    descriptor, temporary_name = mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise AgentIntegrationError(f"cannot update {path}") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _load_profile(path: Path) -> dict[str, Any]:
    # Agy 1.1.x accepts a newly created zero-byte modern profile as an empty
    # server set. Match that documented client behavior without weakening the
    # strict JSON requirement for any non-empty profile or for owned state.
    profile = _load_json_object(
        path,
        absent={"mcpServers": {}},
        label="Antigravity MCP profile",
        allow_empty=True,
    )
    servers = profile.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise AgentIntegrationError("Antigravity MCP profile mcpServers must be an object")
    profile["mcpServers"] = servers
    return profile


def _load_state(path: Path) -> dict[str, Any]:
    state = _load_json_object(
        path, absent={"schemaVersion": _STATE_SCHEMA, "connections": {}}, label="agent connection state"
    )
    if state.get("schemaVersion") != _STATE_SCHEMA or not isinstance(state.get("connections"), dict):
        raise AgentIntegrationError("agent connection state has an unsupported shape")
    return state


def _descriptor(*, catalog: Path, python: Path | None) -> dict[str, Any]:
    selected_catalog = Path(catalog)
    if not selected_catalog.is_absolute() or not selected_catalog.is_dir():
        raise AgentIntegrationError("catalog must be an existing absolute directory")
    interpreter = Path(python) if python is not None else Path(sys.executable)
    if not interpreter.is_absolute() or not interpreter.exists() or not interpreter.is_file():
        raise AgentIntegrationError("Limitless Python interpreter is unavailable")
    return {
        "command": str(interpreter.resolve()),
        "args": ["-m", "limitless_library.mcp_server", "--catalog", str(selected_catalog.resolve())],
    }


def _record(*, profile_path: Path, descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent": ANTIGRAVITY_AGENT,
        "serverName": SERVER_NAME,
        "profilePath": str(profile_path),
        "descriptor": descriptor,
    }


def _stored_descriptor(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("agent") != ANTIGRAVITY_AGENT or value.get("serverName") != SERVER_NAME:
        return None
    descriptor = value.get("descriptor")
    if not isinstance(descriptor, dict):
        return None
    command = descriptor.get("command")
    args = descriptor.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        return None
    return {"command": command, "args": args}


def _profile_descriptor(profile: dict[str, Any]) -> dict[str, Any] | None:
    entry = profile["mcpServers"].get(SERVER_NAME)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise AgentIntegrationError("existing Limitless Antigravity MCP entry is malformed")
    command = entry.get("command")
    args = entry.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise AgentIntegrationError("existing Limitless Antigravity MCP entry is malformed")
    return {"command": command, "args": args}


def _report(
    *, action: str, status: str, reason: str, profile_path: Path, state_path: Path, descriptor: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "schemaVersion": _REPORT_SCHEMA,
        "action": action,
        "agent": ANTIGRAVITY_AGENT,
        "serverName": SERVER_NAME,
        "status": status,
        "reason": reason,
        "profilePath": str(profile_path),
        "statePath": str(state_path),
        "descriptor": descriptor,
        "generatedAt": utc_now(),
    }


def antigravity_connection_status(*, home: Path | None = None, state_path: Path | None = None) -> dict[str, Any]:
    """Inspect the current connection without creating or changing a file."""

    selected_home = _home(home)
    profile_path = _antigravity_profile_path(selected_home)
    selected_state = _state_path(home=selected_home, state_path=state_path)
    profile = _load_profile(profile_path)
    state = _load_state(selected_state)
    current = _profile_descriptor(profile)
    owned = _stored_descriptor(state["connections"].get(ANTIGRAVITY_AGENT))
    if current is None:
        return _report(
            action="status",
            status="not-connected",
            reason="entry-absent" if owned is None else "plugin-entry-absent",
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=owned,
        )
    if owned is None:
        return _report(
            action="status",
            status="attention",
            reason="existing-unmanaged-entry",
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=current,
        )
    if current != owned:
        return _report(
            action="status",
            status="attention",
            reason="plugin-entry-modified",
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=current,
        )
    return _report(
        action="status",
        status="connected",
        reason="configured",
        profile_path=profile_path,
        state_path=selected_state,
        descriptor=current,
    )


def connect_antigravity(
    catalog: Path,
    *,
    home: Path | None = None,
    state_path: Path | None = None,
    python: Path | None = None,
) -> dict[str, Any]:
    """Add one plugin-owned local Library server to Antigravity's MCP profile."""

    selected_home = _home(home)
    profile_path = _antigravity_profile_path(selected_home)
    selected_state = _state_path(home=selected_home, state_path=state_path)
    descriptor = _descriptor(catalog=catalog, python=python)
    profile = _load_profile(profile_path)
    state = _load_state(selected_state)
    current = _profile_descriptor(profile)
    owned = _stored_descriptor(state["connections"].get(ANTIGRAVITY_AGENT))
    if current is not None:
        if current == descriptor and owned == descriptor:
            return _report(
                action="connect",
                status="connected",
                reason="already-configured",
                profile_path=profile_path,
                state_path=selected_state,
                descriptor=descriptor,
            )
        reason = "plugin-entry-modified" if owned is not None else "existing-unmanaged-entry"
        return _report(
            action="connect",
            status="skipped",
            reason=reason,
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=current,
        )
    profile["mcpServers"][SERVER_NAME] = descriptor
    _write_json(profile_path, profile, mode=0o600)
    verified = _profile_descriptor(_load_profile(profile_path))
    if verified != descriptor:
        raise AgentIntegrationError("Antigravity MCP entry could not be verified")
    state["connections"][ANTIGRAVITY_AGENT] = _record(profile_path=profile_path, descriptor=descriptor)
    state["updatedAt"] = utc_now()
    _write_json(selected_state, state, mode=0o600)
    return _report(
        action="connect",
        status="connected",
        reason="configured",
        profile_path=profile_path,
        state_path=selected_state,
        descriptor=descriptor,
    )


def disconnect_antigravity(*, home: Path | None = None, state_path: Path | None = None) -> dict[str, Any]:
    """Remove only the exact Antigravity MCP entry this library recorded."""

    selected_home = _home(home)
    profile_path = _antigravity_profile_path(selected_home)
    selected_state = _state_path(home=selected_home, state_path=state_path)
    profile = _load_profile(profile_path)
    state = _load_state(selected_state)
    owned = _stored_descriptor(state["connections"].get(ANTIGRAVITY_AGENT))
    if owned is None:
        return _report(
            action="disconnect",
            status="skipped",
            reason="not-plugin-owned",
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=None,
        )
    current = _profile_descriptor(profile)
    if current is not None and current != owned:
        return _report(
            action="disconnect",
            status="skipped",
            reason="plugin-entry-modified",
            profile_path=profile_path,
            state_path=selected_state,
            descriptor=current,
        )
    if current is not None:
        del profile["mcpServers"][SERVER_NAME]
        _write_json(profile_path, profile, mode=0o600)
    del state["connections"][ANTIGRAVITY_AGENT]
    state["updatedAt"] = utc_now()
    _write_json(selected_state, state, mode=0o600)
    return _report(
        action="disconnect",
        status="disconnected",
        reason="removed" if current is not None else "already-absent",
        profile_path=profile_path,
        state_path=selected_state,
        descriptor=owned,
    )
