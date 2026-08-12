"""Fail-closed, no-network verifier execution under Bubblewrap."""

from __future__ import annotations

import os
import selectors
import shutil

# Bubblewrap is invoked with an explicit argv and never through a shell.
import subprocess  # nosec B404
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - Linux is the alpha's supported verifier host.
    resource = None

from .contracts import ContractError, regular_file_under, sha256_file, strict_json_loads


class SandboxError(RuntimeError):
    """The receiver verifier could not be safely contained or interpreted."""


MAX_OUTPUT_BYTES = 1024 * 1024
READ_BLOCK_BYTES = 64 * 1024
# This path exists only inside the new Bubblewrap mount namespace.
SANDBOX_TMP = "/tmp"  # nosec B108
SANDBOX_RUNTIME = Path("/runtime")
STANDARD_RUNTIME_ROOTS = (Path("/usr"), Path("/usr/local"), Path("/lib"), Path("/lib64"), Path("/bin"))
# These are reject-only comparisons, never locations where Limitless creates files.
BROAD_RUNTIME_ROOTS = {
    Path("/"),
    Path("/home"),
    Path("/opt"),
    Path("/srv"),
    Path("/tmp"),  # nosec B108
    Path("/var"),
}


def _relative_to(executable: Path, root: Path) -> Path | None:
    try:
        return executable.relative_to(root)
    except ValueError:
        return None


def _python_runtime() -> tuple[Path, Path | None]:
    try:
        executable = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise SandboxError("Python interpreter cannot be resolved") from error
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SandboxError("Python interpreter is not an executable regular file")

    for root in STANDARD_RUNTIME_ROOTS:
        relative = _relative_to(executable, root)
        if relative is not None:
            return executable, None

    seen: set[Path] = set()
    for configured in (sys.prefix, sys.base_prefix):
        try:
            root = Path(configured).resolve(strict=True)
        except OSError:
            continue
        if root in seen or root in BROAD_RUNTIME_ROOTS or not root.is_dir():
            continue
        seen.add(root)
        relative = _relative_to(executable, root)
        if relative is not None:
            return SANDBOX_RUNTIME / relative, root
    raise SandboxError("Python interpreter is outside the contained runtime mounts")


def contained_python() -> str:
    executable, _ = _python_runtime()
    return str(executable)


def _runtime_binds() -> list[str]:
    result: list[str] = []
    for candidate in STANDARD_RUNTIME_ROOTS:
        if Path(candidate).exists():
            result.extend(["--ro-bind", str(candidate), str(candidate)])
    _, runtime_root = _python_runtime()
    if runtime_root is not None:
        result.extend(["--ro-bind", str(runtime_root), str(SANDBOX_RUNTIME)])
    return result


def _limits(timeout: int) -> None:
    if resource is None:
        raise SandboxError("resource limits are unavailable on this platform")
    resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _run_bounded(command: Sequence[str], timeout: int, environment: Mapping[str, str]) -> tuple[int, bytes, bytes]:
    try:
        # The command is fully rendered below and uses the default shell=False.
        process = subprocess.Popen(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            # This library never starts verifier subprocesses from worker
            # threads. POSIX pre-exec limits are part of the fail-closed
            # containment profile, not application customization.
            preexec_fn=lambda: _limits(timeout),  # noqa: PLW1509
        )
    except (OSError, SandboxError, subprocess.SubprocessError) as error:
        raise SandboxError(f"cannot start contained verifier: {error}") from error
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise SandboxError("contained verifier output pipes are unavailable")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    started = time.monotonic()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    _terminate(process)
                    raise SandboxError(f"verifier exceeded {timeout} wall seconds")
                ready = selector.select(remaining)
                if not ready:
                    _terminate(process)
                    raise SandboxError(f"verifier exceeded {timeout} wall seconds")
                for key, _ in ready:
                    block = os.read(key.fileobj.fileno(), READ_BLOCK_BYTES)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    if len(output[name]) + len(block) > MAX_OUTPUT_BYTES:
                        _terminate(process)
                        raise SandboxError(f"verifier exceeded the {MAX_OUTPUT_BYTES}-byte {name} limit")
                    output[name].extend(block)
        exit_code = process.wait()
    except BaseException:
        if process.poll() is None:
            _terminate(process)
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    return exit_code, bytes(output["stdout"]), bytes(output["stderr"])


def _render_argv(argv: list[str]) -> list[str]:
    replacements = {"{python}": contained_python(), "{receiver}": "/work"}
    result: list[str] = []
    for item in argv:
        if item in replacements:
            result.append(replacements[item])
        elif "{" in item or "}" in item or "\x00" in item:
            raise SandboxError("verifier argv may use only {python} and {receiver} placeholders")
        else:
            result.append(item)
    return result


def run_receiver_verifier(
    verifier: dict[str, Any],
    receiver: Path,
    *,
    asset_digest: str,
) -> dict[str, Any]:
    """Run one digest-bound receiver verifier and return strict JSON."""

    bwrap = shutil.which("bwrap")
    if bwrap is None or resource is None:
        raise SandboxError("Bubblewrap and POSIX resource limits are required; no host fallback is permitted")
    try:
        source = regular_file_under(receiver, verifier["source"]["path"], "verifier source")
    except ContractError as error:
        raise SandboxError(str(error)) from error
    if sha256_file(source) != verifier["source"]["digest"]:
        raise SandboxError(f"verifier bytes differ: {verifier['id']}")
    command = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        SANDBOX_TMP,
        "--ro-bind",
        str(receiver.resolve()),
        "/work",
        "--chdir",
        "/work",
        "--clearenv",
        "--setenv",
        "HOME",
        "/nonexistent",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "PYTHONNOUSERSITE",
        "1",
        "--setenv",
        "LIMITLESS_ASSET_DIGEST",
        asset_digest,
        *_runtime_binds(),
        "--",
        *_render_argv(verifier["argv"]),
    ]
    exit_code, stdout, stderr = _run_bounded(
        command,
        verifier["maxWallSeconds"],
        {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
    )
    if exit_code != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()[:1000]
        raise SandboxError(f"verifier {verifier['id']} exited {exit_code}: {detail}")
    try:
        decoded = strict_json_loads(stdout.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise SandboxError(f"verifier {verifier['id']} did not return strict JSON") from error
    if not isinstance(decoded, dict):
        raise SandboxError(f"verifier {verifier['id']} result must be an object")
    return decoded
