"""Bounded stdio MCP adapter for local query-before-work."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import CatalogError, LocalCatalog
from .contracts import strict_json_loads
from .mcp_protocol import (
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    SERVER_INFO_META_KEY,
    has_modern_metadata,
    jsonrpc_error,
    jsonrpc_result,
    modern_request_error,
)
from .schemas import load_schema

SERVER_NAME = "limitless-library"
TOOL_NAME = "limitless_query_before_work"
MAX_REQUEST_BYTES = 1024 * 1024
SERVER_INSTRUCTIONS = "Query before material work; locally verify any selected bytes before adoption."


def _tool() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "description": "Select one permissioned exact component or source-free method, or abstain.",
        "inputSchema": load_schema("query-0.1.schema.json"),
        "outputSchema": load_schema("decision-0.1.schema.json"),
    }


def _modern(registry: LocalCatalog, message: dict[str, Any]) -> dict[str, Any]:
    error = modern_request_error(message)
    if error is not None:
        return error
    message_id = message["id"]
    method = message.get("method")
    if method == "server/discover":
        return jsonrpc_result(
            message_id,
            {
                "resultType": "complete",
                "supportedVersions": [MODERN_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": False}},
                "instructions": SERVER_INSTRUCTIONS,
                "ttlMs": 3600000,
                "cacheScope": "public",
                "_meta": {SERVER_INFO_META_KEY: {"name": SERVER_NAME, "version": __version__}},
            },
        )
    if method == "tools/list":
        return jsonrpc_result(
            message_id,
            {"resultType": "complete", "tools": [_tool()], "ttlMs": 3600000, "cacheScope": "public"},
        )
    if method == "tools/call":
        params = message["params"]
        if params.get("name") != TOOL_NAME or not isinstance(params.get("arguments"), dict):
            return jsonrpc_error(message_id, -32602, f"tools/call requires {TOOL_NAME} arguments")
        try:
            decision = registry.query(params["arguments"])
        except CatalogError as error:
            return jsonrpc_result(
                message_id,
                {"resultType": "complete", "content": [{"type": "text", "text": str(error)}], "isError": True},
            )
        return jsonrpc_result(
            message_id,
            {
                "resultType": "complete",
                "content": [{"type": "text", "text": json.dumps(decision, sort_keys=True)}],
                "structuredContent": decision,
                "isError": False,
            },
        )
    return jsonrpc_error(message_id, -32601, f"method not found: {method}")


def handle_message(registry: LocalCatalog, message: dict[str, Any]) -> dict[str, Any] | None:
    if has_modern_metadata(message):
        return _modern(registry, message)
    message_id = message.get("id")
    method = message.get("method")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        params = message.get("params")
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        if requested != LEGACY_PROTOCOL_VERSION:
            return jsonrpc_error(message_id, -32602, f"unsupported protocolVersion; expected {LEGACY_PROTOCOL_VERSION}")
        return jsonrpc_result(
            message_id,
            {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
                "instructions": SERVER_INSTRUCTIONS,
            },
        )
    if method == "tools/list":
        return jsonrpc_result(message_id, {"tools": [_tool()]})
    if method == "tools/call":
        params = message.get("params")
        if (
            not isinstance(params, dict)
            or params.get("name") != TOOL_NAME
            or not isinstance(params.get("arguments"), dict)
        ):
            return jsonrpc_error(message_id, -32602, f"tools/call requires {TOOL_NAME} arguments")
        try:
            decision = registry.query(params["arguments"])
        except CatalogError as error:
            return jsonrpc_result(message_id, {"content": [{"type": "text", "text": str(error)}], "isError": True})
        return jsonrpc_result(
            message_id,
            {
                "content": [{"type": "text", "text": json.dumps(decision, sort_keys=True)}],
                "structuredContent": decision,
                "isError": False,
            },
        )
    return jsonrpc_error(message_id, -32601, f"method not found: {method}") if "id" in message else None


def _bounded_lines(stream: Any) -> Iterator[tuple[str | None, str | None]]:
    while True:
        raw = stream.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_REQUEST_BYTES or (len(raw) == MAX_REQUEST_BYTES and not raw.endswith(b"\n")):
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(MAX_REQUEST_BYTES + 1)
            yield None, f"MCP request exceeds {MAX_REQUEST_BYTES} bytes"
            continue
        try:
            yield raw.decode("utf-8"), None
        except UnicodeDecodeError:
            yield None, "MCP request is not UTF-8 JSON"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    args = parser.parse_args()
    try:
        catalog = LocalCatalog(args.catalog)
    except CatalogError as error:
        print(f"cannot load catalog: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    legacy_initialized = False
    for line, framing_error in _bounded_lines(sys.stdin.buffer):
        if framing_error:
            response = jsonrpc_error(None, -32700, framing_error)
        else:
            try:
                message = strict_json_loads(line)
                if not isinstance(message, dict):
                    raise TypeError("JSON-RPC message must be an object")
                method = message.get("method")
                if not has_modern_metadata(message) and not legacy_initialized and method != "initialize":
                    response = jsonrpc_error(message.get("id"), -32600, "legacy MCP requires initialize first")
                else:
                    response = handle_message(catalog, message)
                    if method == "initialize" and isinstance(response, dict) and "result" in response:
                        legacy_initialized = True
            except (TypeError, ValueError, CatalogError) as error:
                response = jsonrpc_error(None, -32700, str(error))
        if response is not None:
            print(json.dumps(response, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
