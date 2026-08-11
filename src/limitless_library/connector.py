"""Small local and bounded stdio connector surfaces."""

from __future__ import annotations

import json
import os
import select

# The operator selects a bounded stdio argv; this module never enables a shell.
import subprocess  # nosec B404
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Self

from .catalog import LocalCatalog
from .contracts import sha256_json, strict_json_loads, without
from .mcp_protocol import modern_metadata
from .mcp_server import TOOL_NAME
from .schemas import SchemaError, validate


def query_local(catalog: Path | LocalCatalog, request: dict[str, Any]) -> dict[str, Any]:
    """Query a local catalog without transport or model calls."""

    loaded = catalog if isinstance(catalog, LocalCatalog) else LocalCatalog(catalog)
    return loaded.query(request)


class ConnectorError(RuntimeError):
    """A selected stdio peer returned an invalid or unbound decision."""


def validate_connector_decision(decision: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    try:
        validate(decision, "decision-0.1.schema.json", "connector decision")
    except SchemaError as error:
        raise ConnectorError(str(error)) from error
    if decision["decisionDigest"] != sha256_json(without(decision, "decisionDigest")):
        raise ConnectorError("connector decision digest differs")
    if decision["requestDigest"] != sha256_json(request):
        raise ConnectorError("connector decision is not bound to this request")
    return decision


class McpStdioConnector:
    """Minimal synchronous MCP 2026 connector for one Limitless tool."""

    def __init__(
        self,
        command: list[str],
        *,
        timeout_seconds: float = 10.0,
        environment: Mapping[str, str] | None = None,
    ):
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise ValueError("MCP command must be a non-empty string list")
        if timeout_seconds <= 0:
            raise ValueError("MCP timeout must be positive")
        if environment is not None and any(
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(value, str)
            or "\x00" in value
            for key, value in environment.items()
        ):
            raise ValueError("MCP environment must contain safe string names and values")
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.environment = dict(environment or {})
        self._process: subprocess.Popen[bytes] | None = None
        self._next_id = 1
        self._stdout_buffer = bytearray()

    def __enter__(self) -> Self:
        try:
            # Explicit argv with the default shell=False is the connector boundary.
            self._process = subprocess.Popen(  # nosec B603
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONNOUSERSITE": "1", **self.environment},
            )
        except OSError as error:
            raise ConnectorError(f"cannot start MCP command: {error}") from error
        return self

    def __exit__(self, *_: object) -> None:
        if self._process is None:
            return
        if self._process.stdin:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        for stream in (self._process.stdout, self._process.stderr):
            if stream:
                stream.close()
        self._process = None

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise ConnectorError("MCP connector is not open")
        request_id = self._next_id
        self._next_id += 1
        params = {**params, "_meta": modern_metadata(client_name="limitless-library-python", client_version="0.1.0a0")}
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        encoded = json.dumps(message, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        if len(encoded) > 1024 * 1024:
            raise ConnectorError("MCP request exceeds the 1 MiB connector limit")
        try:
            process.stdin.write(encoded)
            process.stdin.flush()
        except OSError as error:
            raise ConnectorError("cannot write MCP request") from error
        deadline = time.monotonic() + self.timeout_seconds
        while b"\n" not in self._stdout_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectorError(f"MCP {method} timed out")
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                raise ConnectorError(f"MCP {method} timed out")
            try:
                block = os.read(process.stdout.fileno(), 64 * 1024)
            except OSError as error:
                raise ConnectorError("cannot read MCP response") from error
            self._stdout_buffer.extend(block)
            if len(self._stdout_buffer) > 1024 * 1024:
                raise ConnectorError("MCP response exceeds the 1 MiB connector limit")
            if not block:
                break
        if b"\n" in self._stdout_buffer:
            line, _, remainder = self._stdout_buffer.partition(b"\n")
            self._stdout_buffer = bytearray(remainder)
            chunks = bytes(line)
        else:
            chunks = bytes(self._stdout_buffer)
            self._stdout_buffer.clear()
        if not chunks and process.poll() is not None:
            detail = ""
            if process.stderr is not None:
                detail = process.stderr.read(8193).decode("utf-8", errors="replace")[:8192].strip()
            raise ConnectorError(f"MCP peer exited before replying: {detail}")
        try:
            response = strict_json_loads(chunks.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise ConnectorError("MCP response is not strict UTF-8 JSON") from error
        if not isinstance(response, dict) or response.get("id") != request_id:
            raise ConnectorError("MCP response id differs")
        if "error" in response:
            raise ConnectorError(f"MCP {method} failed: {response['error']}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise ConnectorError("MCP response has no object result")
        return result

    def query(self, request: dict[str, Any]) -> dict[str, Any]:
        self._request("server/discover", {})
        listing = self._request("tools/list", {})
        if [tool.get("name") for tool in listing.get("tools", [])] != [TOOL_NAME]:
            raise ConnectorError("MCP peer does not expose the expected sole tool")
        result = self._request("tools/call", {"name": TOOL_NAME, "arguments": request})
        if result.get("isError") is not False or not isinstance(result.get("structuredContent"), dict):
            raise ConnectorError("MCP tool call did not return structured decision content")
        return validate_connector_decision(result["structuredContent"], request)
