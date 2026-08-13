"""Small MCP 2026-07-28 and initialization-era JSON-RPC helpers."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .contracts import canonical_json_bytes, strict_json_loads

LEGACY_PROTOCOL_VERSION = "2025-03-26"
STABLE_PROTOCOL_VERSION = "2025-06-18"
MODERN_PROTOCOL_VERSION = "2026-07-28"
INITIALIZATION_PROTOCOL_VERSIONS = (STABLE_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION)
SUPPORTED_PROTOCOL_VERSIONS = (MODERN_PROTOCOL_VERSION, *INITIALIZATION_PROTOCOL_VERSIONS)
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"


class McpToolCallError(ValueError):
    """A tool request was validly framed but could not produce content."""


class McpToolDispatcher:
    """Dual-era MCP envelope for one bounded, synchronous tool catalog.

    The caller owns schemas, business validation, and side effects. This class
    owns only discovery/list/call protocol envelopes and never starts a
    transport, reads environment state, or grants tool authority.
    """

    def __init__(
        self,
        *,
        server_name: str,
        server_version: str,
        instructions: str,
        tools: Sequence[Mapping[str, Any]],
        call_tool: Callable[[str, dict[str, Any]], Mapping[str, Any]],
        ttl_ms: int = 3_600_000,
        cache_scope: str = "public",
    ) -> None:
        if not server_name.strip() or not server_version.strip() or not instructions.strip():
            raise ValueError("MCP server name, version, and instructions are required")
        if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int) or ttl_ms <= 0:
            raise ValueError("MCP ttl_ms must be a positive integer")
        if cache_scope not in {"public", "private"}:
            raise ValueError("MCP cache_scope must be public or private")
        normalized: list[dict[str, Any]] = []
        names: set[str] = set()
        for raw in tools:
            tool = copy.deepcopy(dict(raw))
            name = tool.get("name")
            if (
                not {"name", "description", "inputSchema", "outputSchema"}.issubset(tool)
                or not set(tool).issubset(
                    {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
                )
                or not isinstance(name, str)
                or not name
                or name in names
                or not isinstance(tool.get("description"), str)
                or not tool["description"]
                or not isinstance(tool.get("inputSchema"), dict)
                or not isinstance(tool.get("outputSchema"), dict)
                or ("title" in tool and (not isinstance(tool["title"], str) or not tool["title"]))
                or not _valid_tool_annotations(tool.get("annotations"))
            ):
                raise ValueError("MCP tools must be unique, complete schema descriptors")
            names.add(name)
            normalized.append(tool)
        if not normalized:
            raise ValueError("MCP tool catalog must not be empty")
        if not callable(call_tool):
            raise TypeError("MCP call_tool must be callable")
        self.server_name = server_name.strip()
        self.server_version = server_version.strip()
        self.instructions = instructions.strip()
        self.tools = tuple(normalized)
        self._tool_names = frozenset(names)
        self.call_tool = call_tool
        self.ttl_ms = ttl_ms
        self.cache_scope = cache_scope

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one strict-decoded JSON-RPC request without session state."""

        if has_modern_metadata(message):
            error = modern_request_error(message)
            if error is not None:
                return error
            return self._modern(message)
        return self._legacy(message)

    def _modern(self, message: dict[str, Any]) -> dict[str, Any]:
        message_id = message["id"]
        method = message.get("method")
        if method == "server/discover":
            return jsonrpc_result(
                message_id,
                {
                    "resultType": "complete",
                    "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                    "capabilities": {"tools": {"listChanged": False}},
                    "instructions": self.instructions,
                    "ttlMs": self.ttl_ms,
                    "cacheScope": self.cache_scope,
                    "_meta": {
                        SERVER_INFO_META_KEY: {
                            "name": self.server_name,
                            "version": self.server_version,
                        }
                    },
                },
            )
        if method == "tools/list":
            request_error = _tools_list_request_error(message)
            if request_error is not None:
                return request_error
            return jsonrpc_result(
                message_id,
                {
                    "resultType": "complete",
                    "tools": copy.deepcopy(list(self.tools)),
                    "ttlMs": self.ttl_ms,
                    "cacheScope": self.cache_scope,
                    "_meta": self._server_info_meta(),
                },
            )
        if method == "tools/call":
            call_error = self._call_request_error(message)
            if call_error is not None:
                return call_error
            return jsonrpc_result(message_id, self._call(message, modern=True))
        return jsonrpc_error(message_id, -32601, f"method not found: {method}")

    def _legacy(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_error = legacy_request_error(message)
        if request_error is not None:
            return request_error
        message_id = message.get("id")
        method = message.get("method")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            params = message.get("params")
            initialize_error = _legacy_initialize_request_error(message)
            if initialize_error is not None:
                return initialize_error
            if not isinstance(params, dict):
                return jsonrpc_error(message_id, -32602, "initialize requires object params")
            requested = params["protocolVersion"]
            return jsonrpc_result(
                message_id,
                {
                    "protocolVersion": requested,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": self.server_name, "version": self.server_version},
                    "instructions": self.instructions,
                },
            )
        if method == "tools/list":
            request_error = _tools_list_request_error(message)
            if request_error is not None:
                return request_error
            return jsonrpc_result(message_id, {"tools": copy.deepcopy(list(self.tools))})
        if method == "tools/call":
            call_error = self._call_request_error(message)
            if call_error is not None:
                return call_error
            return jsonrpc_result(message_id, self._call(message, modern=False))
        return jsonrpc_error(message_id, -32601, f"method not found: {method}") if "id" in message else None

    def _call(self, message: dict[str, Any], *, modern: bool) -> dict[str, Any]:
        params = message["params"]
        name = params.get("name")
        arguments = params.get("arguments")
        try:
            structured = self.call_tool(name, copy.deepcopy(arguments))
        except McpToolCallError as error:
            return self._tool_error(str(error), modern=modern)
        if not isinstance(structured, Mapping):
            raise TypeError("MCP call_tool must return an object")
        try:
            text = canonical_json_bytes(dict(structured)).decode("utf-8")
            safe_structured = strict_json_loads(text)
        except (TypeError, ValueError):
            return self._tool_error("tool result cannot be encoded as strict JSON", modern=modern)
        payload: dict[str, Any] = {
            "content": [
                {
                    "type": "text",
                    "text": text,
                }
            ],
            "structuredContent": safe_structured,
            "isError": False,
        }
        if modern:
            payload["resultType"] = "complete"
            payload["_meta"] = self._server_info_meta()
        return payload

    def _call_request_error(self, message: dict[str, Any]) -> dict[str, Any] | None:
        params = message.get("params")
        if not isinstance(params, dict):
            return jsonrpc_error(message.get("id"), -32602, "tools/call requires object params")
        if params.get("name") not in self._tool_names or not isinstance(params.get("arguments"), dict):
            return jsonrpc_error(
                message.get("id"),
                -32602,
                "tools/call requires one listed tool and object arguments",
            )
        return None

    def _server_info_meta(self) -> dict[str, dict[str, str]]:
        return {SERVER_INFO_META_KEY: {"name": self.server_name, "version": self.server_version}}

    def _tool_error(self, message: str, *, modern: bool) -> dict[str, Any]:
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }
        if modern:
            result["resultType"] = "complete"
            result["_meta"] = self._server_info_meta()
        return result


class McpToolSession:
    """Track only the state required by initialization-era MCP clients.

    Modern MCP remains stateless and bypasses this bit. The session carries no
    tool, tenant, credential, or authorization state.
    """

    def __init__(self, dispatcher: McpToolDispatcher) -> None:
        if not isinstance(dispatcher, McpToolDispatcher):
            raise TypeError("MCP session requires an McpToolDispatcher")
        self.dispatcher = dispatcher
        self.legacy_initialized = False
        self.legacy_ready = False

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if has_modern_metadata(message):
            return self.dispatcher.handle(message)
        method = message.get("method")
        if (
            "id" not in message
            and message.get("jsonrpc") == "2.0"
            and isinstance(method, str)
            and method.startswith("notifications/")
        ):
            if method == "notifications/initialized" and self.legacy_initialized:
                self.legacy_ready = True
            return None
        if method == "initialize":
            response = self.dispatcher.handle(message)
            if isinstance(response, dict) and "result" in response:
                self.legacy_initialized = True
                self.legacy_ready = False
            return response
        if not self.legacy_ready:
            return jsonrpc_error(
                message.get("id"),
                -32600,
                "legacy MCP requires initialize and notifications/initialized before requests",
            )
        return self.dispatcher.handle(message)


def jsonrpc_error(message_id: Any, code: int, message: str, *, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def jsonrpc_result(message_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": payload}


def has_modern_metadata(message: dict[str, Any]) -> bool:
    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
        return False
    return PROTOCOL_VERSION_META_KEY in params["_meta"]


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
        or not isinstance(message.get("method"), str)
        or not message["method"]
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
    if client is not None and not _valid_implementation(client):
        return jsonrpc_error(message_id, -32600, "clientInfo requires non-empty name and version")
    return None


def legacy_request_error(message: dict[str, Any]) -> dict[str, Any] | None:
    """Reject malformed initialization-era requests before tool dispatch."""

    message_id = message.get("id")
    method = message.get("method")
    if message.get("jsonrpc") != "2.0" or not isinstance(method, str) or not method:
        return jsonrpc_error(message_id, -32600, "legacy requests require JSON-RPC 2.0 and a method")
    if "id" in message and (
        message_id is None or isinstance(message_id, (bool, list, dict))
    ):
        return jsonrpc_error(
            message_id,
            -32600,
            "legacy request id must be a string or number",
        )
    if method in {"initialize", "tools/list", "tools/call"} and "id" not in message:
        return jsonrpc_error(
            None,
            -32600,
            "legacy MCP request methods require an id",
        )
    if method == "notifications/initialized" and "id" in message:
        return jsonrpc_error(
            message_id,
            -32600,
            "legacy initialized notification must not include an id",
        )
    return None


def _legacy_initialize_request_error(message: dict[str, Any]) -> dict[str, Any] | None:
    """Validate the client fields required by initialization-era MCP."""

    message_id = message.get("id")
    params = message.get("params")
    if not isinstance(params, dict):
        return jsonrpc_error(message_id, -32602, "initialize requires object params")
    requested = params.get("protocolVersion")
    if requested not in INITIALIZATION_PROTOCOL_VERSIONS:
        return jsonrpc_error(
            message_id,
            -32602,
            "unsupported protocolVersion; expected one of " + ", ".join(INITIALIZATION_PROTOCOL_VERSIONS),
        )
    if not isinstance(params.get("capabilities"), dict):
        return jsonrpc_error(message_id, -32602, "initialize requires object client capabilities")
    if not _valid_implementation(params.get("clientInfo")):
        return jsonrpc_error(message_id, -32602, "initialize requires clientInfo name and version")
    return None


def _valid_tool_annotations(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict) or not set(value).issubset(
        {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
    ):
        return False
    if "title" in value and (not isinstance(value["title"], str) or not value["title"]):
        return False
    return all(
        isinstance(value[key], bool)
        for key in {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}.intersection(value)
    )


def _valid_implementation(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("name"), str)
        and bool(value["name"])
        and isinstance(value.get("version"), str)
        and bool(value["version"])
    )


def _tools_list_request_error(message: dict[str, Any]) -> dict[str, Any] | None:
    params = message.get("params", {})
    if not isinstance(params, dict):
        return jsonrpc_error(message.get("id"), -32602, "tools/list requires object params")
    if "cursor" in params:
        return jsonrpc_error(message.get("id"), -32602, "tools/list does not support cursors")
    return None
