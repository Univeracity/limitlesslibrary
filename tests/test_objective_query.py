from __future__ import annotations

import json
import os
import subprocess
import sys
from base64 import urlsafe_b64decode
from datetime import UTC, datetime
from pathlib import Path

import pytest

from limitless_library.catalog import LocalCatalog
from limitless_library.contracts import canonical_json_bytes, load_json
from limitless_library.mcp_protocol import modern_metadata
from limitless_library.mcp_server import OBJECTIVE_TOOL_NAME, REGISTER_METHOD_TOOL_NAME
from limitless_library.method_capture import CapturedMethodCatalog, register_method
from limitless_library.method_projection import project_method_capsule
from limitless_library.objective_query import (
    ObjectiveQueryEngine,
    ObjectiveQueryError,
    load_query_record,
    validate_objective_result,
)
from limitless_library.query_policy import (
    QueryPolicyError,
    default_query_policy,
    load_query_policy,
    resolve_receivers,
    save_query_policy,
)
from limitless_library.service_connector import ServiceConnector, ServiceHttpResponse, ServiceProfile, VerifiedService
from limitless_library.service_contracts import build_service_query_result, validate_service_query
from limitless_library.service_identity import InstallationSigner

ROOT = Path(__file__).parents[1]
AT = datetime(2026, 8, 20, 22, 0, 30, tzinfo=UTC)


def capture(store: Path, *, title: str = "Verify observed adoption") -> dict:
    return register_method(
        store,
        {
            "title": title,
            "taskKind": "receiver-verification",
            "method": load_json(ROOT / "examples/publication/method.json"),
            "observedOutcome": "The receiver observed the component in use.",
            "platform": "any",
        },
    )


def engine(tmp_path: Path, *, connector_factory=None, catalog: LocalCatalog | None = None) -> ObjectiveQueryEngine:
    options = {"connector_factory": connector_factory} if connector_factory is not None else {}
    return ObjectiveQueryEngine(
        CapturedMethodCatalog(catalog or LocalCatalog.empty(tmp_path / "catalog"), tmp_path / "methods"),
        policy_path=tmp_path / "query-policy.json",
        state_dir=tmp_path / "queries",
        now=lambda: AT.isoformat().replace("+00:00", "Z"),
        **options,
    )


def no_service():
    raise AssertionError("local selection must not connect to the service")


def test_oversized_utf8_policy_cannot_replace_a_usable_saved_policy(tmp_path: Path) -> None:
    path = tmp_path / "query-policy.json"
    policy = default_query_policy()
    save_query_policy(path, policy)
    original = path.read_bytes()
    large = {
        **policy,
        "localReceiver": {"constraints": [f"{index:02d}" + "界" * 198 for index in range(32)], "toolchain": {}},
    }
    with pytest.raises(QueryPolicyError, match="byte limit"):
        save_query_policy(path, large)
    assert path.read_bytes() == original
    assert load_query_policy(path) == policy


def test_objective_uses_private_capture_and_keeps_a_recoverable_local_binding(tmp_path: Path) -> None:
    captured = capture(tmp_path / "methods")
    view = engine(tmp_path, connector_factory=no_service).check({"objective": "Verify observed adoption"})
    assert view["origin"] == "local" and view["treatment"] == "source-free-method"
    assert view["coverage"] == {"local": "complete", "service": "disabled", "continuation": "available"}
    assert view["nextAction"] == "apply-method-and-check"
    assert view["assurance"]["outcome"] == "not-asserted"
    validate_objective_result(view)
    saved = load_query_record(tmp_path / "queries", view["queryRef"])
    assert saved["objective"] == "Verify observed adoption"
    assert saved["localMatch"]["decision"]["selected"]["capsule"]["id"].endswith(captured["methodRef"][7:])
    assert saved["serviceQuery"] is saved["serviceResult"] is None
    assert next((tmp_path / "queries").glob("query-*.json")).stat().st_mode & 0o077 == 0
    assert not (tmp_path / "query-policy.json").exists()


@pytest.mark.parametrize("objective", ["Verify monitor wake", "Check network drivers", "Update package signing"])
def test_incidental_action_words_do_not_select_unrelated_guidance(tmp_path: Path, objective: str) -> None:
    capture(tmp_path / "methods")
    view = engine(tmp_path, connector_factory=no_service).check({"objective": objective})
    assert view["treatment"] == "abstain" and view["selection"] is None


def test_new_route_finds_relevant_lower_priority_work_without_changing_legacy_selection(tmp_path: Path) -> None:
    catalog_root = tmp_path / "catalog"
    for name, title, priority in (
        ("unrelated", "Database transactions", 900),
        ("related", "Symlink record safety", 100),
    ):
        directory = catalog_root / name
        directory.mkdir(parents=True)
        capsule = project_method_capsule(
            capsule_id="capsule:" + name,
            offer_id="offer:" + name,
            version="1.0.0",
            title=title,
            task_kind="operational-safety",
            method={
                "summary": title,
                "steps": ["Apply the stated procedure."],
                "verification": ["The receiver's checks pass."],
            },
            compatibility={"constraints": [], "toolchain": {}},
            priority=priority,
        )
        (directory / "capsule.json").write_bytes(canonical_json_bytes(capsule))
    catalog = LocalCatalog(catalog_root)
    request = {
        "schemaVersion": "limitless.query/0.1",
        "objective": "Symlink record safety",
        "taskKind": "operational-safety",
        "receiver": {"constraints": [], "toolchain": {}},
        "requestedUse": "instantiate",
        "tenantScope": "private",
        "evaluatedAt": AT.isoformat(),
    }
    assert catalog.query(request)["decision"] == "abstain"
    view = engine(tmp_path, catalog=catalog, connector_factory=no_service).check({"objective": request["objective"]})
    assert view["selection"]["reference"] == "offer:related"
    saved = load_query_record(tmp_path / "queries", view["queryRef"])
    catalog.validate_decision(saved["localMatch"]["decision"], request=saved["localMatch"]["request"])


def test_exact_selection_requires_configured_receiver_and_does_not_install(tmp_path: Path) -> None:
    catalog = LocalCatalog(ROOT / "examples/catalog")
    policy = default_query_policy()
    policy.update(
        {
            "requestedUses": ["development"],
            "localReceiver": {"constraints": ["language:python", "runtime:any"], "toolchain": {"python": "3.12"}},
        }
    )
    save_query_policy(tmp_path / "query-policy.json", policy)
    instance = engine(tmp_path, catalog=catalog, connector_factory=no_service)
    first = instance.check({"objective": "Hello component"})
    assert first["treatment"] == "source-free-method"
    policy["allowExact"] = True
    save_query_policy(tmp_path / "query-policy.json", policy)
    second = instance.check({"objective": "Hello component"})
    assert second["treatment"] == "exact-component"
    assert second["nextAction"] == "verify-before-adoption"
    saved = load_query_record(tmp_path / "queries", second["queryRef"])
    assert (
        catalog.selected_capsule_root(saved["localMatch"]["decision"])
        == (ROOT / "examples/catalog/hello-component").resolve()
    )
    assert not list(tmp_path.rglob("greeting.py"))


def test_target_facts_come_from_configured_receiver_not_the_agent_host(tmp_path: Path) -> None:
    policy = default_query_policy()
    remote = load_json(ROOT / "examples/receiver-context.json")
    remote["targets"][0].update({"platform": "windows", "architecture": "arm64"})
    policy["serviceReceiver"] = remote
    local, service = resolve_receivers(policy)
    assert local["constraints"] == ["windows"]
    assert service["targets"][0]["platform"] == "windows"
    assert service["execution"]["platform"] == remote["execution"]["platform"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"objective": " "},
        {"objective": "x" * 481},
        {"objective": "bad\x00text"},
        {"objective": "adoption", "executionMode": "service"},
        {"objective": "adoption", "receiver": {}},
    ],
)
def test_agent_cannot_supply_policy_paths_receiver_facts_or_invalid_objectives(tmp_path: Path, arguments: dict) -> None:
    with pytest.raises(ObjectiveQueryError):
        engine(tmp_path, connector_factory=no_service).check(arguments)
    assert not (tmp_path / "queries").exists()


def test_policy_is_private_and_a_changed_digest_is_observed_without_restart(tmp_path: Path) -> None:
    path = tmp_path / "query-policy.json"
    assert load_query_policy(path)["executionMode"] == "local"
    policy = default_query_policy()
    policy["executionMode"] = "service"
    save_query_policy(path, policy)
    assert load_query_policy(path)["executionMode"] == "service"
    policy["executionMode"] = "local"
    save_query_policy(path, policy)
    assert load_query_policy(path)["executionMode"] == "local"
    path.chmod(0o644)
    with pytest.raises(QueryPolicyError):
        load_query_policy(path)


def test_record_tampering_and_unsafe_storage_do_not_create_false_continuation(tmp_path: Path) -> None:
    capture(tmp_path / "methods")
    instance = engine(tmp_path, connector_factory=no_service)
    view = instance.check({"objective": "Observed adoption"})
    record_path = next((tmp_path / "queries").glob("query-*.json"))
    record = load_json(record_path)
    record["payload"]["objective"] = "changed"
    record_path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ObjectiveQueryError, match="changed"):
        load_query_record(tmp_path / "queries", view["queryRef"])
    instance.state_dir = tmp_path / "unsafe"
    instance.state_dir.mkdir(mode=0o755)
    view = instance.check({"objective": "Observed adoption"})
    assert view["treatment"] == "source-free-method"
    assert view["queryRef"] is None and view["coverage"]["continuation"] == "unavailable"


class SignedQueryTransport:
    def __init__(self, corpus: dict, signer: InstallationSigner, *, exact: bool = False):
        self.corpus = corpus
        self.signer = signer
        self.exact = exact
        self.status = 200
        self.corrupt = False
        self.calls = []

    def request(self, method, url, *, headers, body, maximum_bytes, timeout_seconds):
        assert method == "POST" and url.endswith("/v1/queries")
        query = validate_service_query(json.loads(body), at=AT)
        self.calls.append(query)
        if self.status != 200:
            return ServiceHttpResponse(status=self.status, headers={"content-type": "application/json"}, body=b"{}")
        if self.exact:
            selection = self.corpus["result"]["selection"]
            action = self.corpus["result"]["nextAction"]
            treatment = "exact-component"
        else:
            method_record = load_json(ROOT / "examples/publication/method.json")
            selection = {
                "capabilityId": "capability:observed-adoption",
                "title": "Observed adoption",
                "summary": method_record["summary"],
                "cardDigest": "sha256:" + "4" * 64,
                "compatibility": {
                    "runtime": "any",
                    "versionRange": "any",
                    "interfaces": ["limitless.mcp/v1"],
                    "platforms": ["any"],
                    "architectures": ["any"],
                },
                "allowedUses": ["derive-method"],
                "provenance": {
                    "source": "https://example.com/method",
                    "publisher": "fixture",
                    "license": "CC0-1.0",
                    "reviewState": "reviewed",
                    "reviewEvidence": [],
                },
                "confidence": "medium",
                "rationale": "Matched the declared receiver.",
                "supplyAuthorityId": "public",
                "method": method_record,
            }
            steps = [
                {
                    "instruction": step["instruction"],
                    "check": step["check"],
                    "expected": step["expected"],
                    "locator": "none",
                    "inRepo": False,
                }
                for step in method_record["steps"]
            ]
            action = {
                "kind": "apply-method-step",
                "instruction": steps[0]["instruction"],
                "checks": [{"id": "first", "predicate": steps[0]["check"], "expected": steps[0]["expected"]}],
                "localReuseAvailable": True,
                "stepIndex": 1,
                "steps": steps,
                "locator": "none",
            }
            treatment = "source-free-method"
        result = build_service_query_result(
            query=query,
            decision_ref="decision:objective-contract-test",
            authorized_scopes=["public"],
            policy_digest=self.corpus["discovery"]["dataUsePolicy"]["digest"],
            treatment=treatment,
            selection=selection,
            next_action=action,
            index_generation=13,
            issued_at=AT,
            signer=self.signer,
        )
        if self.corrupt:
            result["selection"]["title"] = "Altered after signing"
        return ServiceHttpResponse(
            status=200, headers={"content-type": "application/json"}, body=canonical_json_bytes(result)
        )


def signed_connector(*, exact: bool = False):
    corpus = load_json(ROOT / "src/limitless_library/conformance/public-service-lifecycle-1.1.json")
    signer = InstallationSigner.generate()
    transport = SignedQueryTransport(corpus, signer, exact=exact)
    root = corpus["rootPublicKey"]
    connector = ServiceConnector(
        ServiceProfile(
            api_base_url=corpus["discovery"]["apiBaseUrl"],
            service_id=corpus["discovery"]["serviceId"],
            root_key_id=root["keyId"],
            root_public_key=urlsafe_b64decode(root["publicKey"] + "=" * ((4 - len(root["publicKey"]) % 4) % 4)),
            accepted_policy_digest=corpus["discovery"]["dataUsePolicy"]["digest"],
            requested_audiences=("public",),
            access_token="fixture-" + "session-value",
        ),
        transport=transport,
        clock=lambda: AT,
    )
    connector._cached = VerifiedService(
        discovery=corpus["discovery"], root_transitions={}, result_keys={signer.key_id: signer.public_bytes()}
    )
    connector._cached_until = float("inf")
    return connector, transport, corpus


def test_service_is_separately_authorized_and_signature_is_checked(tmp_path: Path) -> None:
    connector, transport, _ = signed_connector()
    instance = engine(tmp_path, connector_factory=lambda: connector)
    assert instance.check({"objective": "Observed adoption"})["treatment"] == "abstain"
    assert transport.calls == []
    policy = default_query_policy()
    policy["executionMode"] = "service"
    save_query_policy(tmp_path / "query-policy.json", policy)
    view = instance.check({"objective": "Observed adoption"})
    assert view["origin"] == "service" and view["treatment"] == "source-free-method"
    assert view["assurance"]["selectionIntegrity"] == "service-signature"
    assert transport.calls[-1]["receiverContext"]["allowedUse"] == "derive-method"
    assert transport.calls[-1]["requestedTreatments"] == ["source-free-method"]
    saved = load_query_record(tmp_path / "queries", view["queryRef"])
    assert saved["serviceResult"]["signature"]["keyId"] == transport.signer.key_id
    transport.corrupt = True
    view = instance.check({"objective": "Observed adoption"})
    assert view["treatment"] == "abstain" and view["coverage"]["service"] == "verification-failed"
    policy["executionMode"] = "local"
    save_query_policy(tmp_path / "query-policy.json", policy)
    calls = len(transport.calls)
    assert instance.check({"objective": "Observed adoption"})["coverage"]["service"] == "disabled"
    assert len(transport.calls) == calls


def test_service_failure_leaves_fresh_local_work_available(tmp_path: Path) -> None:
    connector, transport, _ = signed_connector()
    transport.status = 503
    policy = default_query_policy()
    policy["executionMode"] = "service"
    save_query_policy(tmp_path / "query-policy.json", policy)
    view = engine(tmp_path, connector_factory=lambda: connector).check({"objective": "Observed adoption"})
    assert view["nextAction"] == "start-fresh" and view["coverage"]["service"] == "unavailable"


def test_local_hit_skips_service_and_policy_revocation_prevents_objective_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = default_query_policy()
    policy["executionMode"] = "service"
    save_query_policy(tmp_path / "query-policy.json", policy)
    capture(tmp_path / "methods")
    view = engine(tmp_path, connector_factory=no_service).check({"objective": "Observed adoption"})
    assert view["origin"] == "local" and view["coverage"]["service"] == "not-needed"

    connector, transport, _ = signed_connector()
    build = connector.build_query

    def revoke(**options):
        query = build(**options)
        save_query_policy(tmp_path / "query-policy.json", default_query_policy())
        return query

    monkeypatch.setattr(connector, "build_query", revoke)
    view = engine(tmp_path, connector_factory=lambda: connector).check({"objective": "Unrelated database cleanup"})
    assert view["treatment"] == "abstain" and view["reason"] == "query-policy-changed"
    assert transport.calls == []


def test_exact_service_credentials_are_only_in_private_continuation(tmp_path: Path) -> None:
    connector, transport, corpus = signed_connector(exact=True)
    policy = default_query_policy()
    policy.update(
        {"executionMode": "service", "allowExact": True, "serviceReceiver": corpus["query"]["receiverContext"]}
    )
    save_query_policy(tmp_path / "query-policy.json", policy)
    view = engine(tmp_path, connector_factory=lambda: connector).check({"objective": "Clipboard history"})
    assert view["treatment"] == "exact-component" and view["nextAction"] == "verify-before-adoption"
    credential = corpus["result"]["selection"]["immutable"]["authorization"]["value"]
    assert credential not in json.dumps(view)
    saved = load_query_record(tmp_path / "queries", view["queryRef"])
    assert saved["serviceResult"]["selection"]["immutable"]["authorization"]["value"] == credential
    assert len(transport.calls) == 1  # Query only, never GET bytes or execute.


def test_real_stdio_captures_then_checks_without_a_seed_catalog(tmp_path: Path) -> None:
    method = {
        "title": "Observed adoption",
        "taskKind": "receiver-verification",
        "method": load_json(ROOT / "examples/publication/method.json"),
        "observedOutcome": "Receiver checks passed.",
        "platform": "any",
    }
    requests = []
    for index, (name, arguments) in enumerate(
        ((REGISTER_METHOD_TOOL_NAME, method), (OBJECTIVE_TOOL_NAME, {"objective": "Observed adoption"})), 1
    ):
        requests.append(
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                    "_meta": modern_metadata(client_name="objective-test", client_version="1"),
                },
            }
        )
    response = subprocess.run(
        [sys.executable, "-m", "limitless_library.mcp_server", "--method-store", str(tmp_path / "methods")],
        input="".join(json.dumps(item) + "\n" for item in requests),
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    replies = [json.loads(line)["result"]["structuredContent"] for line in response.stdout.splitlines()]
    assert replies[0]["status"] == "registered"
    assert replies[1]["treatment"] == "source-free-method"
