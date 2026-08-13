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
    McpToolCallError,
    McpToolDispatcher,
    McpToolSession,
    jsonrpc_error,
)
from .schemas import load_schema

SERVER_NAME = "limitless-library"
TOOL_NAME = "limitless_query_before_work"
MAX_REQUEST_BYTES = 1024 * 1024
SERVER_INSTRUCTIONS = "Query before material work; locally verify any selected bytes before adoption."


def _tool() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "title": "Query before work",
        "description": "Select one permissioned exact component or source-free method, or abstain.",
        "inputSchema": load_schema("query-0.1.schema.json"),
        "outputSchema": load_schema("decision-0.1.schema.json"),
        "annotations": {
            "readOnlyHint": True,
            "openWorldHint": False,
        },
    }


def handle_message(registry: LocalCatalog, message: dict[str, Any]) -> dict[str, Any] | None:
    return _dispatcher(registry).handle(message)


def _dispatcher(registry: LocalCatalog) -> McpToolDispatcher:
    def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name != TOOL_NAME:
            raise McpToolCallError("tool is not available")
        try:
            return registry.query(arguments)
        except CatalogError as error:
            raise McpToolCallError(str(error)) from error

    return McpToolDispatcher(
        server_name=SERVER_NAME,
        server_version=__version__,
        instructions=SERVER_INSTRUCTIONS,
        tools=[_tool()],
        call_tool=call_tool,
    )


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
    session = McpToolSession(_dispatcher(catalog))
    for line, framing_error in _bounded_lines(sys.stdin.buffer):
        if framing_error:
            response = jsonrpc_error(None, -32700, framing_error)
        else:
            try:
                message = strict_json_loads(line)
                if not isinstance(message, dict):
                    raise TypeError("JSON-RPC message must be an object")
                response = session.handle(message)
            except (TypeError, ValueError, CatalogError) as error:
                response = jsonrpc_error(None, -32700, str(error))
        if response is not None:
            print(json.dumps(response, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
