"""Small MCP 2026-07-28 and legacy JSON-RPC helpers."""

from __future__ import annotations

from typing import Any

LEGACY_PROTOCOL_VERSION = "2025-03-26"
MODERN_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = (MODERN_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION)
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"


def jsonrpc_error(message_id: Any, code: int, message: str, *, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def jsonrpc_result(message_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": payload}


def has_modern_metadata(message: dict[str, Any]) -> bool:
    params = message.get("params")
    return isinstance(params, dict) and "_meta" in params


def modern_metadata(*, client_name: str, client_version: str) -> dict[str, Any]:
    return {
        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
        CLIENT_INFO_META_KEY: {"name": client_name, "version": client_version},
        CLIENT_CAPABILITIES_META_KEY: {},
    }


def modern_request_error(message: dict[str, Any]) -> dict[str, Any] | None:
    message_id = message.get("id")
    if (
        message.get("jsonrpc") != "2.0"
        or "id" not in message
        or message_id is None
        or isinstance(message_id, (bool, list, dict))
    ):
        return jsonrpc_error(message_id, -32600, "modern requests require JSON-RPC 2.0 and a string or number id")
    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
        return jsonrpc_error(message_id, -32600, "modern requests require object params._meta")
    meta = params["_meta"]
    requested = meta.get(PROTOCOL_VERSION_META_KEY)
    if requested != MODERN_PROTOCOL_VERSION:
        return jsonrpc_error(
            message_id,
            -32022,
            "Unsupported protocol version",
            data={"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "requested": requested},
        )
    if not isinstance(meta.get(CLIENT_CAPABILITIES_META_KEY), dict):
        return jsonrpc_error(message_id, -32600, "modern requests require object client capabilities")
    client = meta.get(CLIENT_INFO_META_KEY)
    if client is not None and not (
        isinstance(client, dict)
        and isinstance(client.get("name"), str)
        and bool(client["name"])
        and isinstance(client.get("version"), str)
        and bool(client["version"])
    ):
        return jsonrpc_error(message_id, -32600, "clientInfo requires non-empty name and version")
    return None
