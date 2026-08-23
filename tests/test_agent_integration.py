from __future__ import annotations

import json
from pathlib import Path

from limitless_library.agent_integration import (
    SERVER_NAME,
    antigravity_connection_status,
    connect_antigravity,
    disconnect_antigravity,
)


def _paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    state = tmp_path / "state" / "agent-connections.json"
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    python = tmp_path / "runtime" / "python"
    python.parent.mkdir()
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    return home, state, catalog, python


def test_connects_legacy_antigravity_profile_without_touching_unrelated_entries(tmp_path: Path) -> None:
    home, state, catalog, python = _paths(tmp_path)
    profile_path = home / ".gemini" / "antigravity" / "mcp_config.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(
        json.dumps(
            {
                "mcpServers": {"unrelated": {"command": "/owner/server", "args": ["--owner"]}},
                "unrelatedSetting": {"keep": True},
            }
        ),
        encoding="utf-8",
    )

    connected = connect_antigravity(catalog, home=home, state_path=state, python=python)

    assert connected["status"] == "connected"
    assert connected["reason"] == "configured"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    assert profile["unrelatedSetting"] == {"keep": True}
    assert profile["mcpServers"]["unrelated"] == {"command": "/owner/server", "args": ["--owner"]}
    assert profile["mcpServers"][SERVER_NAME] == {
        "command": str(python.resolve()),
        "args": ["-m", "limitless_library.mcp_server", "--catalog", str(catalog.resolve())],
    }
    assert profile_path.stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o600
    assert antigravity_connection_status(home=home, state_path=state)["status"] == "connected"

    disconnected = disconnect_antigravity(home=home, state_path=state)

    assert disconnected["status"] == "disconnected"
    cleaned = json.loads(profile_path.read_text(encoding="utf-8"))
    assert SERVER_NAME not in cleaned["mcpServers"]
    assert cleaned["mcpServers"]["unrelated"] == {"command": "/owner/server", "args": ["--owner"]}


def test_prefers_the_migrated_antigravity_profile(tmp_path: Path) -> None:
    home, state, catalog, python = _paths(tmp_path)
    legacy_path = home / ".gemini" / "antigravity" / "mcp_config.json"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    modern_path = home / ".gemini" / "config" / "mcp_config.json"
    modern_path.parent.mkdir(parents=True)
    modern_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

    result = connect_antigravity(catalog, home=home, state_path=state, python=python)

    assert result["profilePath"] == str(modern_path)
    assert SERVER_NAME not in json.loads(legacy_path.read_text(encoding="utf-8"))["mcpServers"]
    assert SERVER_NAME in json.loads(modern_path.read_text(encoding="utf-8"))["mcpServers"]


def test_accepts_the_empty_modern_profile_created_by_antigravity(tmp_path: Path) -> None:
    home, state, catalog, python = _paths(tmp_path)
    modern_path = home / ".gemini" / "config" / "mcp_config.json"
    modern_path.parent.mkdir(parents=True)
    modern_path.touch()

    result = connect_antigravity(catalog, home=home, state_path=state, python=python)

    assert result["status"] == "connected"
    assert json.loads(modern_path.read_text(encoding="utf-8"))["mcpServers"][SERVER_NAME] == {
        "command": str(python.resolve()),
        "args": ["-m", "limitless_library.mcp_server", "--catalog", str(catalog.resolve())],
    }


def test_does_not_overwrite_an_unmanaged_antigravity_entry(tmp_path: Path) -> None:
    home, state, catalog, python = _paths(tmp_path)
    profile_path = home / ".gemini" / "config" / "mcp_config.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(
        json.dumps({"mcpServers": {SERVER_NAME: {"command": "/owner/server", "args": ["--owner"]}}}),
        encoding="utf-8",
    )

    result = connect_antigravity(catalog, home=home, state_path=state, python=python)

    assert result["status"] == "skipped"
    assert result["reason"] == "existing-unmanaged-entry"
    assert json.loads(profile_path.read_text(encoding="utf-8"))["mcpServers"][SERVER_NAME] == {
        "command": "/owner/server",
        "args": ["--owner"],
    }


def test_disconnect_preserves_a_plugin_entry_the_owner_changed(tmp_path: Path) -> None:
    home, state, catalog, python = _paths(tmp_path)
    connect_antigravity(catalog, home=home, state_path=state, python=python)
    profile_path = home / ".gemini" / "config" / "mcp_config.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["mcpServers"][SERVER_NAME] = {"command": "/owner/server", "args": ["--owner"]}
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    result = disconnect_antigravity(home=home, state_path=state)

    assert result["status"] == "skipped"
    assert result["reason"] == "plugin-entry-modified"
    assert json.loads(profile_path.read_text(encoding="utf-8"))["mcpServers"][SERVER_NAME] == {
        "command": "/owner/server",
        "args": ["--owner"],
    }
