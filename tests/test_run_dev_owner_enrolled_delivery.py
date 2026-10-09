from __future__ import annotations

from pathlib import Path
import hashlib
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

import scripts.run_dev_owner_enrolled_delivery as runner


def test_delivery_intent_journal_adapts_schema_envelope_without_changing_core_state(tmp_path):
    state_dir = tmp_path / "delivery-state"
    state_dir.mkdir()
    journal = runner._DeliveryIntentJournal(state_dir)
    state = {"binding": {"run_id": "a" * 32}, "phase": "ready", "receipt": None}
    journal.save(state)
    assert journal.load() == state

    stored = runner.FileJournal(state_dir).load()
    assert stored == {"schema": 1, "delivery_state": state}


def test_delivery_intent_journal_rejects_bad_core_phase_and_envelope(tmp_path):
    state_dir = tmp_path / "delivery-state"
    state_dir.mkdir()
    journal = runner._DeliveryIntentJournal(state_dir)
    with pytest.raises(ValueError, match="^delivery_journal_invalid$"):
        journal.save({"binding": {}, "phase": "unknown", "receipt": None})
    underlying = runner.FileJournal(state_dir)
    underlying.save({"schema": 1, "unexpected": {}})
    with pytest.raises(ValueError, match="^delivery_journal_invalid$"):
        journal.load()


_AUTHORITY = {
    "account_id": "123456789012",
    "operator_arn": "arn:aws:iam::123456789012:user/operator",
    "authorized_from_epoch": 100,
    "authorized_until_epoch": 700,
    "execution_start_epoch": 100,
    "execution_end_epoch": 400,
    "owner_resource_uri": "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp",
    "service_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update",
    "stack_id": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/12345678-1234-1234-1234-123456789abc",
    "operator_arn": "arn:aws:iam::123456789012:user/operator",
}


def _path_inputs(root: Path):
    return {key: root / f"{key}.json" for key in runner._PRIVATE_INPUT_FIELDS}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _ok(value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class _Client:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __getattr__(self, method):
        def call(**kwargs):
            self.calls.append((method, kwargs))
            if not self.replies:
                raise AssertionError("unexpected SDK read")
            reply = self.replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply
        return call


class _Clock:
    def __init__(self, value=200.0):
        self.value = value

    def __call__(self):
        return self.value

    def sleep(self, amount):
        self.value += amount


def test_failed_source_gate_stops_before_clients_or_private_root(tmp_path):
    calls = []

    def fail_source(_authorization):
        calls.append("source")
        raise RuntimeError("redacted")

    result = runner.run_owner_enrolled_delivery_once(
        private_inputs=_path_inputs(tmp_path), wheel_dir=tmp_path, private_parent=tmp_path,
        source_sha="a" * 40, ci_run_id=4, source_validator=fail_source,
        protection_reader=lambda: calls.append("protection"),
        bundle_factory=lambda: calls.append("clients"),
    )

    assert result == {"ok": False, "category": "source_ci_failed",
                      "phase": "stopped", "private_root": None}
    assert calls == ["source"]


def test_protection_ids_must_be_exact_and_are_checked_before_clients():
    calls = []
    result = runner.run_owner_enrolled_delivery_once(
        private_inputs=_path_inputs(Path("unused")), wheel_dir=Path("unused"), private_parent=Path("unused"),
        source_sha="b" * 40, ci_run_id=12,
        source_validator=lambda auth: calls.append(auth["source_sha"]),
        protection_reader=lambda: (True, 8),
        bundle_factory=lambda: calls.append("clients"),
    )

    assert result["category"] == "github_protection_failed"
    assert calls == ["b" * 40]


def test_protection_result_cannot_use_bool_as_numeric_repository_id():
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._protection_check_result({}, lambda **_kwargs: (1, True), 1, 1)
    assert exc.value.category == "github_protection_failed"


def test_private_root_must_be_disjoint_in_both_directions(tmp_path):
    historic = tmp_path / "historic"
    historic.mkdir()
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._require_disjoint_root(historic / "new-run", [historic])
    assert exc.value.category == "private_inputs_unverified"

    nested = historic / "new-run"
    nested.mkdir()
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._require_disjoint_root(historic, [nested])
    assert exc.value.category == "private_inputs_unverified"


def test_poll_waits_only_for_closed_update_and_never_writes():
    clock = _Clock()
    sts = _Client([_ok({"Account": "123456789012", "Arn": _AUTHORITY["operator_arn"]})] * 2)
    api_id = "abcdefghij"
    api = _Client([_ok({"ApiId": api_id, "DisableExecuteApiEndpoint": True})] * 2)
    lam = _Client([_ok({"ReservedConcurrentExecutions": 0})] * 2)
    cfn = _Client([
        _ok({"Stacks": [{"StackId": _AUTHORITY["stack_id"],
                         "StackName": "honda-mapit-mcp-dev-retained",
                         "RoleARN": _AUTHORITY["service_role_arn"],
                         "StackStatus": "UPDATE_IN_PROGRESS"}]}),
        _ok({"Stacks": [{"StackId": _AUTHORITY["stack_id"],
                         "StackName": "honda-mapit-mcp-dev-retained",
                         "RoleARN": _AUTHORITY["service_role_arn"],
                         "StackStatus": "UPDATE_COMPLETE"}]}),
    ])
    clients = {"sts": sts, "apigatewayv2": api, "lambda": lam, "cloudformation": cfn}
    result = runner._poll_update_complete(
        clients, _AUTHORITY, clock=clock, monotonic=clock, sleep=clock.sleep)

    assert result == {"status": "UPDATE_COMPLETE", "polls": 2, "calls": 8}
    assert [call[0] for call in cfn.calls] == ["describe_stacks", "describe_stacks"]
    assert all("update_stack" not in method for method, _ in cfn.calls)


@pytest.mark.parametrize("reply,category", [
    ({"StackStatus": "UPDATE_ROLLBACK_COMPLETE"}, "update_not_accepted"),
    ({"StackStatus": "UPDATE_IN_PROGRESS", "RoleARN": "wrong"}, "current_state_unverified"),
])
def test_poll_fails_closed_on_rollback_or_role_drift(reply, category):
    clock = _Clock()
    clients = {
        "sts": _Client([_ok({"Account": _AUTHORITY["account_id"], "Arn": _AUTHORITY["operator_arn"]})]),
        "apigatewayv2": _Client([_ok({"ApiId": "abcdefghij", "DisableExecuteApiEndpoint": True})]),
        "lambda": _Client([_ok({"ReservedConcurrentExecutions": 0})]),
        "cloudformation": _Client([_ok({"Stacks": [{
            "StackId": _AUTHORITY["stack_id"],
            "StackName": "honda-mapit-mcp-dev-retained",
            "RoleARN": _AUTHORITY["service_role_arn"],
            "StackStatus": "UPDATE_IN_PROGRESS",
            **reply,
        }]})]),
    }
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock,
                                     monotonic=clock, sleep=clock.sleep)
    assert exc.value.category == category


def test_poll_rejects_invalid_caps_before_sdk_calls():
    clients = {name: _Client([]) for name in ("sts", "apigatewayv2", "lambda", "cloudformation")}
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=lambda: 200,
                                     monotonic=lambda: 0, sleep=lambda _n: None,
                                     max_polls=True)
    assert exc.value.category == "current_state_unverified"
    assert all(not client.calls for client in clients.values())


def test_poll_rejects_pagination_before_accepting_stack_status():
    clock = _Clock()
    clients = {
        "sts": _Client([_ok({"Account": _AUTHORITY["account_id"], "Arn": _AUTHORITY["operator_arn"]})]),
        "apigatewayv2": _Client([_ok({"ApiId": "abcdefghij", "DisableExecuteApiEndpoint": True})]),
        "lambda": _Client([_ok({"ReservedConcurrentExecutions": 0})]),
        "cloudformation": _Client([_ok({"Stacks": [{
            "StackId": _AUTHORITY["stack_id"],
            "StackName": "honda-mapit-mcp-dev-retained",
            "RoleARN": _AUTHORITY["service_role_arn"],
            "StackStatus": "UPDATE_COMPLETE",
        }], "NextToken": "must-not-follow"})]),
    }
    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock,
                                     monotonic=clock, sleep=clock.sleep)
    assert exc.value.category == "current_state_unverified"


def test_full_private_loader_to_pre_publish_update_and_accepted_readback(tmp_path, monkeypatch):
    """Run the real owning parsers/core/readback over SDK-shaped fake clients."""
    from tests.test_dev_owner_enrolled_private_inputs import _private_inputs
    from scripts import dev_owner_enrolled_delivery_sdk as delivery_sdk
    from scripts.build_aws_dev_runtime import BuildSummary
    from scripts.dev_owner_enrolled_runtime import build_owner_enrolled_dev_runtime_target
    from mapit.dev_enrolled_manifest import (
        INVITATION_JWKS_FILENAME, MANIFEST_FILENAME, MAPIT_JWKS_FILENAME,
    )
    from scripts.dev_owner_enrolled_runtime_readback import make_owner_enrolled_current_state
    import scripts.dev_identity_binding_runtime_evidence as legacy_runtime_evidence
    from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
    from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template
    from scripts.dev_owner_enrolled_login_lineage import credential_snapshot_from_explicit_credentials
    from tests.owner_enrolled_artifact_fixture import ArtifactResponses
    from scripts.probe_aws_dev_enrolled_arm import CHECKS

    raw_inputs, fixture = _private_inputs(tmp_path / "accepted-inputs")
    # The legacy verifier owns its ACL check rather than accepting the current
    # adapter's injected checker. For this synthetic fixture only, allow its
    # already-created temp-directory journal through that ACL boundary while
    # retaining the real journal parser and all evidence checks.
    monkeypatch.setattr(legacy_runtime_evidence, "validate_private_location",
                        lambda path: Path(path))
    scenario = fixture["scenario"]
    delivery = fixture["delivery"]
    # The shared source/protection fixture uses these repo IDs. Rebind only the
    # synthetic owner/invitation metadata receipts consistently before parsing;
    # the owner context digest and accepted cloud-resource receipts are unchanged.
    owner_binding_path = raw_inputs["owner_oauth_binding_path"]
    owner_binding = json.loads(owner_binding_path.read_bytes())
    owner_binding["github_owner_id"], owner_binding["github_repository_id"] = 12, 34
    # The SDK-shaped owner stack must use the independently trusted permanent
    # owner pool, not the technical pool in the hosted A/B fixture.
    scenario.owner_pool = owner_binding["owner_pool_id"]
    scenario.owner_template = build_dev_owner_oauth_template(
        account_id=scenario.account, api_id=scenario.api_id,
        owner_pool_id=scenario.owner_pool,
        callback_url="http://127.0.0.1:8787/callback")
    scenario.owner_ids["McpUserPool"] = scenario.owner_pool
    owner_binding["authorization_sha256"] = hashlib.sha256(
        _canonical(json.loads(raw_inputs["owner_oauth_authorization_path"].read_bytes()))
    ).hexdigest()
    owner_binding_path.write_bytes(_canonical(owner_binding))
    from scripts.run_aws_closed_rehearsal import FileJournal
    from scripts.dev_owner_oauth_bootstrap import DevOwnerOAuthBootstrapCoordinator
    from scripts.build_aws_dev_owner_oauth import STACK_NAME as OWNER_STACK_NAME
    owner_auth = json.loads(raw_inputs["owner_oauth_authorization_path"].read_bytes())
    owner_sdk = OwnerOAuthSdkBindings(scenario.clients(), account_id=owner_auth["account"],
        operator_user_arn=owner_auth["expected_caller_arn"], until_epoch=owner_auth["end"],
        wall_clock=lambda: owner_auth["start"] + 20, monotonic=lambda: 100.0)
    owner_snapshot = owner_sdk.capture_context(exclude_client_id=delivery.auth["owner_client_id"])
    owner_rows, owner_stack = owner_sdk._stack(OWNER_STACK_NAME, 3)
    owner_candidate = owner_sdk.validate_candidate(owner_stack["stack_id"], scenario.owner_template,
        owner_binding["run_uuid"], owner_auth["start"], owner_auth["end"],
        {name: row["PhysicalResourceId"] for name, row in owner_rows.items()})
    owner_binding["context_sha256"] = owner_snapshot["context_sha256"]
    owner_binding_path.write_bytes(_canonical(owner_binding))
    class NoIO:
        def __getattr__(self, _name):
            def fail(**_kwargs):
                raise AssertionError("historical owner parser attempted SDK I/O")
            return fail
    owner_journal = FileJournal(raw_inputs["owner_oauth_state_dir"])
    owner_state = owner_journal.load()
    owner_coordinator = DevOwnerOAuthBootstrapCoordinator(
        {"cloudformation": NoIO(), "cognito": NoIO()}, owner_journal,
        account_id=owner_auth["account"], operator_user_arn=owner_auth["expected_caller_arn"],
        owner_pool_id=owner_binding["owner_pool_id"], api_id=owner_binding["api_id"],
        callback_url=owner_binding["callback_url"], source_sha=owner_auth["source_sha"],
        run_id=owner_binding["run_uuid"], authorized_from_epoch=owner_auth["start"],
        authorized_until_epoch=owner_auth["end"],
        expected_context_sha256=owner_binding["context_sha256"],
        context_reader=lambda *_: None, source_checker=lambda: False,
        readback_validator=lambda *_: None,
    )
    owner_state.update(
        authority_sha256=owner_coordinator.authority_sha256,
        template_sha256=owner_coordinator.template_sha256,
        intent={"token": owner_coordinator._request_token(), "stack_name": OWNER_STACK_NAME,
                "template_sha256": owner_coordinator.template_sha256},
        readback={"verified": True, "client_id": fixture["delivery"].auth["owner_client_id"],
                  "readback_sha256": owner_candidate["readback_sha256"]},
    )
    owner_journal.save(owner_state)
    from scripts.run_dev_owner_assisted_login import load_trusted_owner_policy
    from scripts.dev_owner_login_context import parse_accepted_owner_login_context
    owner_trusted = load_trusted_owner_policy(raw_inputs["owner_release_receipt"],
        expected_account=owner_auth["account"], acl_checker=lambda _path: True)
    owner_ctx = parse_accepted_owner_login_context(owner_auth, owner_binding, owner_state,
        trusted_owner_policy=owner_trusted)
    assert owner_ctx.policy.user_pool_id == owner_binding["owner_pool_id"]
    assert owner_coordinator._load()["phase"] == "readback_verified"
    invitation_authority_path = raw_inputs["invitation_authorization_path"]
    invitation_authority = json.loads(invitation_authority_path.read_bytes())
    invitation_authority["github_owner_id"], invitation_authority["github_repository_id"] = 12, 34
    invitation_authority["owner_context_sha256"] = owner_binding["context_sha256"]
    invitation_authority_path.write_bytes(_canonical(invitation_authority))
    invitation_journal = FileJournal(raw_inputs["invitation_state_dir"])
    invitation_state = invitation_journal.load()
    invitation_state["authority_sha256"] = hashlib.sha256(_canonical(invitation_authority)).hexdigest()
    invitation_state["owner_context_sha256"] = owner_binding["context_sha256"]
    invitation_journal.save(invitation_state)
    private_inputs = {key: value for key, value in raw_inputs.items()
                      if key in runner._PRIVATE_INPUT_FIELDS}
    # Match the accepted MAPIT runtime evidence used by the fresh source gate.
    # The owner context is reparsed from the edited private binding below.
    github_ids = (12, 34)
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    private_parent = tmp_path / "operator-private"
    private_parent.mkdir()
    clock_value = 1_800_000_100.0
    mono_value = 100.0

    class Clock:
        def __call__(self):
            return clock_value

        def monotonic(self):
            return mono_value

    clock = Clock()
    loaded_holder = {}
    real_make_current_state = make_owner_enrolled_current_state

    def loader(**kwargs):
        kwargs["jwks_fetcher"] = raw_inputs["jwks_fetcher"]
        result = runner.load_owner_enrolled_private_inputs(**kwargs)
        loaded_holder["value"] = result
        return result

    def bundle_factory():
        from scripts.dev_owner_enrolled_delivery_sdk import DeliveryClientBundle
        credential_snapshot = credential_snapshot_from_explicit_credentials(SimpleNamespace(
            access_key="AKIAEXAMPLE123456", secret_key="S" * 40, token=None))
        result = DeliveryClientBundle(scenario.clients(), credential_snapshot)
        delivery_sdk._register_client_bundle(result)
        return result

    def archive_builder(_wheels, manifest, invitation, mapit, output, *, account_id):
        entries = {
            f"mapit/{MANIFEST_FILENAME}": Path(manifest).read_bytes(),
            f"mapit/{INVITATION_JWKS_FILENAME}": Path(invitation).read_bytes(),
            f"mapit/{MAPIT_JWKS_FILENAME}": Path(mapit).read_bytes(),
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(entries.items()):
                archive.writestr(name, data)
        payload = buffer.getvalue()
        Path(output).write_bytes(payload)
        scenario.archive = payload
        return BuildSummary(len(payload), hashlib.sha256(payload).hexdigest(), 28, 3, 1, 2,
                            True, True, True, True)

    def current_state_factory(**kwargs):
        authority = kwargs["authority"]
        scenario.delivery.auth.update(authority)
        scenario.archive = kwargs["archive_bytes"]
        scenario.delivery.coordinator.zip_sha = hashlib.sha256(kwargs["archive_bytes"]).hexdigest()
        scenario.target = build_owner_enrolled_dev_runtime_target(
            prior_template=kwargs["prior_template"],
            mapit_bootstrap_template=loaded_holder["value"].bootstrap_template,
            manifest_raw=kwargs["manifest_raw"], invitation_jwks=kwargs["invitation_jwks"],
            mapit_jwks=kwargs["mapit_jwks"], manifest_sha256=authority["manifest_sha256"],
            account_id=authority["account_id"], source_sha=authority["source_sha"],
            zip_sha256=hashlib.sha256(kwargs["archive_bytes"]).hexdigest(),
            execution_start_epoch=authority["execution_start_epoch"],
            execution_end_epoch=authority["execution_end_epoch"],
        )
        scenario.phase = "pre"
        scenario.artifact_responses = ArtifactResponses(authority, {
            authority["prior_zip_sha256"]: 100,
            hashlib.sha256(kwargs["archive_bytes"]).hexdigest(): len(kwargs["archive_bytes"]),
        })
        cfn = scenario.clients()["cloudformation"]

        def update_stack(**request):
            scenario.calls.append(("cloudformation", "update_stack", request))
            assert request["StackName"] == authority["stack_id"]
            assert request["RoleARN"] == authority["service_role_arn"]
            assert request["ClientRequestToken"] == f"owner-enrolled-{authority['run_id']}"
            assert json.loads(request["TemplateBody"]) == scenario.target
            scenario.phase = "accepted"
            return scenario._ok(StackId=authority["stack_id"])

        cfn.update_stack = update_stack
        current_state = real_make_current_state(**kwargs)
        return current_state

    def put_object(**request):
        scenario.calls.append(("s3", "put_object", request))
        assert request["IfNoneMatch"] == "*"
        assert request["ExpectedBucketOwner"] == delivery.auth["account_id"]
        assert request["Body"] == scenario.archive
        return scenario._ok()

    scenario.clients()["s3"].put_object = put_object
    monkeypatch.setattr(runner, "make_owner_enrolled_current_state", current_state_factory)
    result = runner.run_owner_enrolled_delivery_once(
        private_inputs=private_inputs, wheel_dir=wheel_dir, private_parent=private_parent,
        source_sha=raw_inputs["source_sha"], ci_run_id=88,
        acl_checker=lambda _path: True,
        source_validator=lambda auth: None,
        protection_reader=lambda **_kwargs: github_ids,
        bundle_factory=bundle_factory,
        archive_builder=archive_builder,
        arm_probe=lambda _wheel_dir: {"success": True,
            "category": "enrolled_arm_readiness_passed",
            "checks": {name: True for name in CHECKS}, "wheel_count": 28},
        private_input_loader=loader,
        clock=clock, monotonic=clock.monotonic, sleep=lambda _seconds: None,
    )

    assert result["ok"] is True, result
    assert result["phase"] == "accepted"
    assert result["polls"] == 1
    assert scenario.phase == "accepted"
    assert len([call for call in scenario.calls if call[1] == "put_object"]) == 1
    assert len([call for call in scenario.calls if call[1] == "update_stack"]) == 1
