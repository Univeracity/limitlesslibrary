#!/usr/bin/env python3
"""Exercise unchanged public clients against candidate source, without networking.

Historical code comes from pinned Git archives, never edited compatibility
fixtures. This qualifies source interoperability; installed wheels and live
service continuity remain separate release gates.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CORE = {
    "0.1.0a0": "3681451a66874bc21e7a411a529a3e036b87208e",
    "0.1.0a1": "b9249e8de3e2cf558b70719dcd6e7a2ec44dd352",
}
ORIGINAL_OMARCHY = "c2e303ba63024ee4e1c4cbc595488fa9dfef7170"

CLIENT_PROBE = r"""
import json, os, stat, sys
from pathlib import Path
from limitless_library.connector import McpStdioConnector, query_local
from limitless_library.contracts import load_json

config = json.loads(sys.argv[1])
historical = Path(config["historical"])
owner = Path(config["owner"])
def snapshot():
    return {p.relative_to(owner).as_posix():
            (stat.S_IMODE(p.stat().st_mode), p.read_bytes() if p.is_file() else None)
            for p in owner.rglob("*")}
before = snapshot()
command = [sys.executable, "-m", config["server"], "--catalog", str(historical / "examples/catalog"),
           "--method-store", str(owner / "methods"), "--query-state", str(owner / "queries")]
if config["server"] == "limitless_omarchy.mcp_server":
    command += ["--settings-path", str(owner / "settings.json"), "--drafts-path", str(owner / "drafts")]
with McpStdioConnector(command, environment={"PYTHONPATH": config["candidatePath"]}) as connector:
    decisions = []
    for name in ("exact-python", "method-portable", "abstain"):
        request = load_json(historical / "examples/requests" / (name + ".json"))
        expected = query_local(historical / "examples/catalog", request)
        actual = connector.query(request)
        if actual != expected:
            raise ValueError("historical decision or catalog binding changed: " + name)
        decisions.append({"case": name, "decisionDigest": actual["decisionDigest"],
                          "catalogDigest": actual["catalogDigest"]})
    request = load_json(historical / "examples/requests/exact-python.json")
    request.update(taskKind="compatibility-probe", requestedUse="instantiate", tenantScope="private",
                   objective="Original capture compatibility probe")
    actual = connector.query(request)
    if actual["selected"] is None or actual["selected"]["offer"]["kind"] != "method":
        raise ValueError("original capture was not reusable by the unchanged client: " + json.dumps(actual))
    decisions.append({"case": "original-capture", "decisionDigest": actual["decisionDigest"],
                      "catalogDigest": actual["catalogDigest"]})
after = snapshot()
if after != before:
    raise ValueError("legacy queries wrote or changed owner state")
print(json.dumps({"cases": decisions, "ownerStateUnchanged": True}))
"""

CAPTURE_PRODUCER = r"""
import json, sys
from pathlib import Path
from limitless_library.contracts import load_json
from limitless_library.method_capture import register_method
historical, owner = map(Path, sys.argv[1:])
result = register_method(owner / "methods", {
    "title": "Original capture compatibility probe", "taskKind": "compatibility-probe",
    "method": load_json(historical / "examples/publication/method.json"),
    "observedOutcome": "Synthetic compatibility fixture; not receiver usefulness evidence.",
    "platform": "any",
}, schedule=False)
print(json.dumps(result))
"""

NATIVE_STATE_PROBE = r"""
import json, sys
from pathlib import Path
from limitless_omarchy.drafts import load_draft, register_method
from limitless_omarchy.settings import default_settings, save_settings
phase, owner_name = sys.argv[1:]
owner = Path(owner_name)
registry, catalog, settings = owner / "drafts", owner / "catalog", owner / "settings.json"
value = {"name": "Preserve index identity", "summary": "Bind an index name to its bytes.",
         "steps": ["Compare the existing content digest before accepting the name."],
         "verify": ["Reject a name that already identifies different bytes."]}
if phase == "original-producer":
    save_settings(settings, default_settings())
    result = register_method(registry, catalog, settings, value)
elif phase == "candidate-writer":
    before = {p.relative_to(owner).as_posix(): p.read_bytes() for p in owner.rglob("*.json")}
    parent = json.loads((owner / "parent.json").read_text())
    duplicate = register_method(registry, catalog, settings, value)
    if duplicate != {**parent, "status": "duplicate"}:
        raise ValueError("original draft identity or result shape changed")
    if before != {p.relative_to(owner).as_posix(): p.read_bytes() for p in owner.rglob("*.json")}:
        raise ValueError("duplicate registration changed original state")
    value.update(supersedes=parent["draftRef"], steps=["Compare complete bytes and reject conflicting names."])
    result = register_method(registry, catalog, settings, value)
    for name, raw in before.items():
        if name.startswith("catalog/"):
            continue  # Supersession retires only the parent's projection.
        if (owner / name).read_bytes() != raw:
            raise ValueError("revision rewrote existing records, settings, or sharing state")
elif phase == "original-reader-writer":
    child = json.loads((owner / "child.json").read_text())
    parent = json.loads((owner / "parent.json").read_text())
    record = load_draft(registry, child["draftRef"])
    previous = load_draft(registry, parent["draftRef"])
    if record["revision"] != 2 or record["lineageId"] != previous["lineageId"]:
        raise ValueError("original reader cannot follow the new revision lineage")
    value.update(supersedes=child["draftRef"], steps=["Check bytes before indexing; preserve the prior object."])
    result = register_method(registry, catalog, settings, value)
else:
    grandchild = json.loads((owner / "grandchild.json").read_text())
    record = load_draft(registry, grandchild["draftRef"])
    if record["revision"] != 3:
        raise ValueError("candidate cannot read a revision written by the original plugin")
    result = {"originalStatePreserved": True, "bidirectionalRevisionCompatibility": True}
print(json.dumps(result))
"""


def archive(root: Path, revision: str, destination: Path, *paths: str) -> dict[str, str]:
    data = subprocess.check_output(["git", "-C", str(root), "archive", revision, *paths])
    with tarfile.open(fileobj=io.BytesIO(data)) as source:
        for member in source.getmembers():
            logical = PurePosixPath(member.name)
            if logical.is_absolute() or ".." in logical.parts or not (member.isdir() or member.isfile()):
                raise ValueError("historical archive contains an unsafe member")
            path = destination.joinpath(*logical.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream:
                    path.write_bytes(stream.read())
    return {"commit": revision, "archiveSha256": hashlib.sha256(data).hexdigest()}


def probe(program: str, python_path: list[Path], *arguments: str) -> dict:
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TMPDIR") if key in os.environ}
    environment.update(PYTHONPATH=os.pathsep.join(map(str, python_path)), PYTHONNOUSERSITE="1")
    result = subprocess.run(
        [sys.executable, "-c", program, *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise ValueError("historical interoperability probe failed:\n" + result.stderr.strip())
    return json.loads(result.stdout)


def candidate_source(root: Path, package: str) -> dict[str, str]:
    source = root / "src" / package
    files = [
        (path.relative_to(source).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(source.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".json", ".typed"}
    ]
    return {
        "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip(),
        "packageFingerprint": hashlib.sha256(json.dumps(files, separators=(",", ":")).encode()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-root", type=Path, default=ROOT)
    parser.add_argument("--omarchy-root", type=Path, help="also qualify candidate adapter and original draft state")
    parser.add_argument("--output", type=Path, help="optional machine-readable source compatibility receipt")
    args = parser.parse_args()
    report = {"schemaVersion": "limitless.legacy-source-compatibility/1", "scope": "source-interoperability"}
    report["candidateSource"] = {"core": candidate_source(args.core_root, "limitless_library")}
    if args.omarchy_root:
        report["candidateSource"]["omarchy"] = candidate_source(args.omarchy_root, "limitless_omarchy")
    with tempfile.TemporaryDirectory(prefix="limitless-legacy-") as temporary:
        root = Path(temporary)
        sources = {}
        report["originalSources"] = {}
        for version, revision in ORIGINAL_CORE.items():
            sources[version] = root / version
            report["originalSources"][version] = archive(args.core_root, revision, sources[version], "src", "examples")
        owner = root / "owner"
        owner.mkdir(mode=0o700)
        probe(CAPTURE_PRODUCER, [sources["0.1.0a1"] / "src"], str(sources["0.1.0a1"]), str(owner))
        report["clients"] = []
        candidate_path = [args.core_root.resolve() / "src"]
        servers = ["limitless_library.mcp_server"]
        if args.omarchy_root:
            candidate_path.insert(0, args.omarchy_root.resolve() / "src")
            servers.append("limitless_omarchy.mcp_server")
        for version, historical in sources.items():
            for server in servers:
                config = {
                    "historical": str(historical),
                    "owner": str(owner),
                    "server": server,
                    "candidatePath": os.pathsep.join(map(str, candidate_path)),
                }
                try:
                    result = probe(CLIENT_PROBE, [historical / "src"], json.dumps(config))
                except ValueError as error:
                    raise ValueError(f"{version} against {server}: {error}") from error
                report["clients"].append({"version": version, "candidate": server, **result})
        if args.omarchy_root:
            native = root / "original-omarchy"
            report["originalSources"]["omarchy-0.2.1"] = archive(args.omarchy_root, ORIGINAL_OMARCHY, native, "src")
            old_path = [native / "src", sources["0.1.0a1"] / "src"]
            state = root / "native-state"
            state.mkdir(mode=0o700)
            for phase, path, filename in (
                ("original-producer", old_path, "parent.json"),
                ("candidate-writer", candidate_path, "child.json"),
                ("original-reader-writer", old_path, "grandchild.json"),
                ("candidate-reader", candidate_path, None),
            ):
                result = probe(NATIVE_STATE_PROBE, path, phase, str(state))
                if filename:
                    (state / filename).write_text(json.dumps(result))
                else:
                    report["nativeState"] = result
    report["status"] = "passed"
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
