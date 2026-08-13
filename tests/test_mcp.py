from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from limitless_library.catalog import LocalCatalog
from limitless_library.connector import ConnectorError, McpStdioConnector, validate_connector_decision
from limitless_library.contracts import load_json
from limitless_library.mcp_protocol import (
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    STABLE_PROTOCOL_VERSION,
    McpToolCallError,
    McpToolDispatcher,
    McpToolSession,
    modern_metadata,
)
from limitless_library.mcp_server import SERVER_INSTRUCTIONS, TOOL_NAME, handle_message

ROOT = Path(__file__).parents[1]
CATALOG_PATH = ROOT / "examples" / "catalog"
REQUEST = ROOT / "examples" / "requests" / "exact-python.json"


def _message(method: str, params: dict[str, object], message_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "method": method,
        "params": {**params, "_meta": modern_metadata(client_name="test", client_version="1")},
    }


def _initialize_message(protocol_version: str, message_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "limitless-library-tests", "version": "1"},
        },
    }


def test_modern_mcp_discovers_and_queries_one_structured_tool() -> None:
    catalog = LocalCatalog(CATALOG_PATH)
    discovery = handle_message(catalog, _message("server/discover", {}))
    assert discovery["result"]["supportedVersions"][0] == MODERN_PROTOCOL_VERSION
    listing = handle_message(catalog, _message("tools/list", {}, 2))
    assert [tool["name"] for tool in listing["result"]["tools"]] == [TOOL_NAME]
    assert listing["result"]["tools"][0]["annotations"] == {
        "readOnlyHint": True,
        "openWorldHint": False,
    }
    response = handle_message(
        catalog,
        _message("tools/call", {"name": TOOL_NAME, "arguments": load_json(REQUEST)}, 3),
    )
    assert response["result"]["structuredContent"]["decision"] == "reuse"


@pytest.mark.parametrize("protocol_version", [STABLE_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION])
def test_initialize_eras_preserve_query_first_instructions(protocol_version: str) -> None:
    response = handle_message(
        LocalCatalog(CATALOG_PATH),
        _initialize_message(protocol_version),
    )

    assert response["result"]["protocolVersion"] == protocol_version
    assert response["result"]["instructions"] == SERVER_INSTRUCTIONS


def test_initialize_rejects_missing_required_client_fields() -> None:
    response = handle_message(
        LocalCatalog(CATALOG_PATH),
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": STABLE_PROTOCOL_VERSION},
        },
    )

    assert response["error"]["code"] == -32602


def test_generic_dispatcher_keeps_modern_and_legacy_tools_on_one_handler() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def call_tool(name: str, arguments: dict[str, object]) -> dict[str, object]:
        calls.append((name, arguments))
        return {"echo": arguments["value"]}

    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only; execute nothing.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo one fixture value.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=call_tool,
        cache_scope="private",
    )
    modern = dispatcher.handle(
        _message("tools/call", {"name": "fixture_echo", "arguments": {"value": "modern"}})
    )
    legacy = dispatcher.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "fixture_echo", "arguments": {"value": "legacy"}},
        }
    )

    assert modern["result"]["resultType"] == "complete"
    assert modern["result"]["structuredContent"] == {"echo": "modern"}
    assert "resultType" not in legacy["result"]
    assert legacy["result"]["structuredContent"] == {"echo": "legacy"}
    assert calls == [("fixture_echo", {"value": "modern"}), ("fixture_echo", {"value": "legacy"})]


def test_generic_dispatcher_returns_tool_error_without_hiding_protocol_success() -> None:
    def fail(_name: str, _arguments: dict[str, object]) -> dict[str, object]:
        raise McpToolCallError("held by fixture policy")

    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_hold",
                "description": "Return a held fixture result.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=fail,
    )
    response = dispatcher.handle(
        _message("tools/call", {"name": "fixture_hold", "arguments": {}})
    )

    assert response["result"]["isError"] is True
    assert response["result"]["content"][0]["text"] == "held by fixture policy"
    invalid = dispatcher.handle(
        _message("tools/call", {"name": "unlisted", "arguments": {}})
    )
    assert invalid["error"]["code"] == -32602


@pytest.mark.parametrize("protocol_version", [STABLE_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION])
def test_generic_session_requires_initialize_but_keeps_modern_stateless(
    protocol_version: str,
) -> None:
    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo a fixture object.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=lambda _name, arguments: arguments,
    )
    session = McpToolSession(dispatcher)
    initialization_call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fixture_echo",
            "arguments": {"era": "initialized"},
            "_meta": {"progressToken": 0},
        },
    }
    held = session.handle(initialization_call)
    modern = session.handle(
        _message("tools/call", {"name": "fixture_echo", "arguments": {"era": "modern"}}, 2)
    )
    initialized = session.handle(
        _initialize_message(protocol_version, 3)
    )
    still_held = session.handle(initialization_call)
    initialized_notification = session.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    admitted = session.handle(initialization_call)

    assert held["error"]["code"] == -32600
    assert modern["result"]["structuredContent"] == {"era": "modern"}
    assert initialized["result"]["protocolVersion"] == protocol_version
    assert still_held["error"]["code"] == -32600
    assert initialized_notification is None
    assert admitted["result"]["structuredContent"] == {"era": "initialized"}


def test_legacy_session_rejects_malformed_envelopes_before_tool_dispatch() -> None:
    calls: list[dict[str, object]] = []
    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo a fixture object.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=lambda _name, arguments: calls.append(arguments) or arguments,
    )
    session = McpToolSession(dispatcher)

    malformed_initialize = session.handle(
        {
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": STABLE_PROTOCOL_VERSION},
        }
    )
    still_held = session.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    initialized = session.handle(
        _initialize_message(STABLE_PROTOCOL_VERSION, 3)
    )
    ready = session.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    invalid_id = session.handle(
        {"jsonrpc": "2.0", "id": True, "method": "tools/list", "params": {}}
    )
    missing_id = session.handle(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {}}
    )

    assert malformed_initialize["error"]["code"] == -32600
    assert still_held["error"]["code"] == -32600
    assert initialized["result"]["protocolVersion"] == STABLE_PROTOCOL_VERSION
    assert ready is None
    assert invalid_id["error"]["code"] == -32600
    assert missing_id["error"]["code"] == -32600
    assert calls == []


def test_legacy_session_ignores_notifications_without_responses() -> None:
    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo a fixture object.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=lambda _name, arguments: arguments,
    )
    session = McpToolSession(dispatcher)

    pre_initialize = session.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    cancellation = session.handle(
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}
    )
    initialized = session.handle(_initialize_message(STABLE_PROTOCOL_VERSION))
    final_notification = session.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )

    assert pre_initialize is None
    assert cancellation is None
    assert initialized["result"]["protocolVersion"] == STABLE_PROTOCOL_VERSION
    assert final_notification is None


def test_mcp_rejects_unexpected_tools_list_cursors() -> None:
    modern = handle_message(LocalCatalog(CATALOG_PATH), _message("tools/list", {"cursor": "unexpected"}))
    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo a fixture object.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=lambda _name, arguments: arguments,
    )
    legacy = dispatcher.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "unexpected"}}
    )

    assert modern["error"]["code"] == -32602
    assert legacy["error"]["code"] == -32602


def test_modern_mcp_rejects_non_string_method() -> None:
    message = _message("tools/list", {})
    message["method"] = 7

    response = handle_message(LocalCatalog(CATALOG_PATH), message)

    assert response["error"]["code"] == -32600


def test_mcp_text_content_is_strict_canonical_json() -> None:
    dispatcher = McpToolDispatcher(
        server_name="fixture",
        server_version="1",
        instructions="Inspect only.",
        tools=[
            {
                "name": "fixture_echo",
                "description": "Echo a fixture object.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"},
            }
        ],
        call_tool=lambda _name, _arguments: {"value": "caf\u00e9", "z": 1},
    )

    response = dispatcher.handle(_message("tools/call", {"name": "fixture_echo", "arguments": {}}))

    assert response["result"]["content"][0]["text"] == '{"value":"caf\u00e9","z":1}'
    assert response["result"]["structuredContent"] == {"value": "caf\u00e9", "z": 1}


def test_bounded_stdio_connector_validates_request_binding() -> None:
    command = [sys.executable, "-m", "limitless_library.mcp_server", "--catalog", str(CATALOG_PATH)]
    with McpStdioConnector(command, environment={"PYTHONPATH": str(ROOT / "src")}) as connector:
        decision = connector.query(load_json(REQUEST))
    assert decision["decision"] == "reuse"
    assert decision["selected"]["offer"]["id"] == "offer:hello-python-exact"


def test_stdio_server_completes_initialization_era_lifecycle() -> None:
    request = load_json(REQUEST)
    messages = [
        _initialize_message(STABLE_PROTOCOL_VERSION),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": TOOL_NAME, "arguments": request},
        },
    ]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "limitless_library.mcp_server", "--catalog", str(CATALOG_PATH)],
        input="".join(json.dumps(message) + "\n" for message in messages),
        capture_output=True,
        check=True,
        encoding="utf-8",
        env=environment,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()]

    assert [response["id"] for response in responses] == [1, 2, 3]
    assert responses[0]["result"]["protocolVersion"] == STABLE_PROTOCOL_VERSION
    assert responses[1]["result"]["tools"][0]["name"] == TOOL_NAME
    assert responses[2]["result"]["structuredContent"]["decision"] == "reuse"


def test_modern_mcp_rejects_wrong_protocol_version() -> None:
    message = _message("tools/list", {})
    message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
    response = handle_message(LocalCatalog(CATALOG_PATH), message)
    assert response["error"]["code"] == -32022


def test_connector_rejects_decision_substitution() -> None:
    request = load_json(REQUEST)
    decision = LocalCatalog(CATALOG_PATH).query(request)
    decision["requestDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ConnectorError, match="digest differs|not bound"):
        validate_connector_decision(decision, request)


def test_connector_enforces_response_deadline() -> None:
    command = [sys.executable, "-c", "import time; time.sleep(2)"]
    with McpStdioConnector(command, timeout_seconds=0.1) as connector, pytest.raises(ConnectorError, match="timed out"):
        connector.query(load_json(REQUEST))


def test_connector_enforces_response_size_limit() -> None:
    code = "import sys; sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'x'*(1024*1024+1)); sys.stdout.flush()"
    command = [sys.executable, "-c", code]
    with McpStdioConnector(command) as connector, pytest.raises(ConnectorError, match="1 MiB"):
        connector.query(load_json(REQUEST))
