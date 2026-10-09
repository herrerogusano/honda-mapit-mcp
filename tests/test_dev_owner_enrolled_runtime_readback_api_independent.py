from __future__ import annotations

import pytest

from test_dev_owner_enrolled_runtime_readback import (
    ACCOUNT,
    _build_owner_enrolled_current_state_fixture,
)


def _verify_owner_api_children(fixture, *, accepted):
    import scripts.dev_owner_enrolled_runtime_readback as readback

    scenario = fixture["scenario"]
    template = scenario.target if accepted else scenario.prior
    scenario.phase = "accepted" if accepted else "pre"
    rows = scenario._rows(
        template,
        stack_id=scenario.delivery.auth["stack_id"],
        stack_name="honda-mapit-mcp-dev-retained",
    )
    row_map = {row["LogicalResourceId"]: row for row in rows}
    zip_sha = scenario.delivery.coordinator.zip_sha if accepted else scenario.delivery.auth["prior_zip_sha256"]
    clients = scenario.clients()
    readback._verify_api_and_lambda(
        {"apigatewayv2": clients["apigatewayv2"], "lambda": clients["lambda"]},
        fixture["runtime_binding"],
        template,
        row_map,
        zip_sha,
        accepted=accepted,
    )


def _omit_request_bound_api_id(scenario):
    original_api = scenario._api

    def api_without_request_id(method, kwargs):
        reply = original_api(method, kwargs)
        if method == "get_integrations":
            for item in reply.get("Items", []):
                item.pop("ApiId", None)
        return reply

    scenario._api = api_without_request_id


@pytest.mark.parametrize("accepted", [False, True])
def test_api_child_readback_accepts_sdk_integration_shape_without_request_apid(tmp_path, accepted):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    scenario = fixture["scenario"]
    _omit_request_bound_api_id(scenario)

    # API Gateway returns IntegrationId and integration properties, but not
    # the request's ApiId. The validator must bind through the exact physical
    # IntegrationId and route Target instead of expecting ApiId in each item.
    integration = scenario._api("get_integrations", {"ApiId": scenario.api_id})["Items"][0]
    assert "ApiId" not in integration
    _verify_owner_api_children(fixture, accepted=accepted)


@pytest.mark.parametrize("accepted", [False, True])
@pytest.mark.parametrize("mutation", ["integration_id", "route_id", "route_target"])
def test_api_child_readback_rejects_drifted_physical_bindings(tmp_path, mutation, accepted):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    scenario = fixture["scenario"]
    _omit_request_bound_api_id(scenario)
    original_api = scenario._api

    def drifted_api(method, kwargs):
        reply = original_api(method, kwargs)
        if method == "get_integrations" and mutation == "integration_id":
            reply["Items"][0]["IntegrationId"] = "foreign-integration"
        elif method == "get_routes":
            item = reply["Items"][0]
            if mutation == "route_id":
                item["RouteId"] = "foreign-route"
            elif mutation == "route_target":
                item["Target"] = "integrations/foreign-integration"
        return reply

    scenario._api = drifted_api
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    with pytest.raises(OwnerEnrolledReadbackError):
        _verify_owner_api_children(fixture, accepted=accepted)


def test_current_state_real_loader_pre_and_post_phases(tmp_path, monkeypatch):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    pre = fixture["current"]("pre_update", fixture["delivery_binding"])
    assert pre.get("phase") == "pre_update", {
        "category": pre.get("category"), "stage": pre.get("stage"), "calls": pre.get("calls")}
    pre_auth = scenario._api("get_authorizers", {"ApiId": scenario.api_id})["Items"][0]
    assert pre_auth["JwtConfiguration"]["Issuer"] == (
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Technical12345")
    scenario.phase = "accepted"
    post = fixture["current"]("accepted", fixture["delivery_binding"])
    assert post.get("phase") == "accepted", {
        "category": post.get("category"), "stage": post.get("stage"), "calls": post.get("calls")}
    post_auth = scenario._api("get_authorizers", {"ApiId": scenario.api_id})["Items"][0]
    assert post_auth["JwtConfiguration"]["Issuer"] == (
        f"https://cognito-idp.eu-west-1.amazonaws.com/{fixture['delivery'].auth['owner_pool_id']}")


@pytest.mark.parametrize("slot", [0, 1])
def test_current_state_rejects_historical_tenant_revival_or_revocation(tmp_path, monkeypatch, slot):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    target_key = fixture["delivery"].auth["historical_tenant_keys"][slot]
    original_dispatch = scenario._dispatch

    def changed_history(service, method, kwargs):
        reply = original_dispatch(service, method, kwargs)
        if service == "dynamodb" and method == "get_item" and kwargs.get("Key", {}).get("key", {}).get("S") == target_key:
            reply["Item"]["status"]["S"] = "active" if slot == 0 else "revoked"
        return reply

    scenario._dispatch = changed_history
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("pre_update", fixture["delivery_binding"])


@pytest.mark.parametrize("drift", ["resource_id", "table_id"])
def test_current_state_rejects_post_preupdate_physical_drift(tmp_path, monkeypatch, drift):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    pre = fixture["current"]("pre_update", fixture["delivery_binding"])
    assert pre.get("phase") == "pre_update", pre
    scenario.phase = "accepted"
    original_dispatch = scenario._dispatch

    def drifted_read(service, method, kwargs):
        reply = original_dispatch(service, method, kwargs)
        if drift == "resource_id" and service == "cloudformation" and method == "list_stack_resources":
            if kwargs.get("StackName") == fixture["delivery"].auth["stack_id"]:
                next(row for row in reply["StackResourceSummaries"]
                     if row.get("LogicalResourceId") == "McpApi")["PhysicalResourceId"] = "foreign-api"
        if drift == "table_id" and service == "dynamodb" and method == "describe_table":
            if kwargs.get("TableName") == "honda-mapit-mcp-dev-tenants":
                reply["Table"]["TableId"] = "44444444-4444-4444-8444-444444444444"
        return reply

    scenario._dispatch = drifted_read
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("accepted", fixture["delivery_binding"])


@pytest.mark.parametrize("field", ["status", "revision"])
def test_current_state_rejects_owner_row_status_or_revision_drift(tmp_path, monkeypatch, field):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    owner_key = fixture["delivery"].auth["owner_tenant_key"]
    original_dispatch = scenario._dispatch

    def drifted_owner(service, method, kwargs):
        reply = original_dispatch(service, method, kwargs)
        if service == "dynamodb" and method == "get_item" and kwargs.get("Key", {}).get("key", {}).get("S") == owner_key:
            if field == "status":
                reply["Item"]["status"]["S"] = "revoked"
            else:
                reply["Item"]["revision"]["N"] = "2"
        return reply

    scenario._dispatch = drifted_owner
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("pre_update", fixture["delivery_binding"])


def test_current_state_rejects_final_sts_identity_mismatch(tmp_path, monkeypatch):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    original_dispatch = scenario._dispatch

    def drift_final_identity(service, method, kwargs):
        if (service == "sts" and method == "get_caller_identity" and len(scenario.calls) >= 2
                and scenario.calls[-2][0:2] == ("lambda", "get_function_concurrency")):
            return scenario._ok(Account="000000000000", Arn="arn:aws:iam::000000000000:user/foreign")
        return original_dispatch(service, method, kwargs)

    scenario._dispatch = drift_final_identity
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("pre_update", fixture["delivery_binding"])


def test_current_state_rejects_duplicate_artifact_tag_keys(tmp_path, monkeypatch):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    original_dispatch = scenario._dispatch

    def duplicate_tag(service, method, kwargs):
        reply = original_dispatch(service, method, kwargs)
        if service == "s3" and method == "get_bucket_tagging":
            # Identical duplicate values are still a malformed AWS readback;
            # don't let dict construction silently normalize the response.
            reply["TagSet"].append({"Key": "Project", "Value": "honda-mapit-mcp"})
        return reply

    scenario._dispatch = duplicate_tag
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("pre_update", fixture["delivery_binding"])
    assert any(service == "s3" and method == "get_bucket_tagging"
               for service, method, _kwargs in scenario.calls)


@pytest.mark.parametrize("field", ["RoleName", "PolicyName"])
def test_current_state_rejects_mismatched_get_role_policy_response_binding(tmp_path, monkeypatch, field):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    original_dispatch = scenario._dispatch

    def mismatch_policy_response(service, method, kwargs):
        reply = original_dispatch(service, method, kwargs)
        if service == "iam" and method == "get_role_policy":
            reply[field] = "foreign-role" if field == "RoleName" else "foreign-policy"
        return reply

    scenario._dispatch = mismatch_policy_response
    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("pre_update", fixture["delivery_binding"])
    assert any(service == "iam" and method == "get_role_policy"
               for service, method, _kwargs in scenario.calls)


@pytest.mark.parametrize("field", ["RoleName", "PolicyName"])
def test_role_policy_document_response_must_echo_exact_requested_identity(field):
    import copy
    from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
    from scripts.dev_owner_enrolled_runtime_readback import _verify_role
    import scripts.dev_owner_enrolled_runtime_readback as readback
    from test_dev_owner_enrolled_runtime_readback import _Iam
    from test_dev_mapit_runtime_evidence import _app_template, _authority_and_bundle

    authority, _bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn="arn:aws:iam::123456789012:user/operator",
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
        ssm_key_arn="arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    mapit = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    role_properties = app_template["Resources"]["McpHandlerRole"]["Properties"]
    policies = {item["PolicyName"]: copy.deepcopy(item["PolicyDocument"])
                for item in role_properties["Policies"]}
    policies[synthetic["PolicyName"]] = copy.deepcopy(synthetic["PolicyDocument"])
    policies[mapit["PolicyName"]] = copy.deepcopy(mapit["PolicyDocument"])
    role = {"Arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-handler-role",
            "PermissionsBoundary": None,
            "AssumeRolePolicyDocument": copy.deepcopy(role_properties["AssumeRolePolicyDocument"])}
    view = {"iam": _Iam(role, policies)}
    template = copy.deepcopy(app_template)
    template["__mapit_runtime_policy"] = copy.deepcopy(mapit)
    rows = {"McpHandlerRole": {"PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler-role"}}
    original = view["iam"].get_role_policy

    def mismatched(*, RoleName, PolicyName):
        reply = original(RoleName=RoleName, PolicyName=PolicyName)
        reply[field] = "foreign-role" if field == "RoleName" else "foreign-policy"
        return reply

    view["iam"].get_role_policy = mismatched
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        _verify_role(view, {"account_id": ACCOUNT}, template, rows,
                     accepted=True, synthetic_policy=synthetic["PolicyDocument"])


def test_delivery_coordinator_runs_full_current_state_preflight_publish_update_and_acceptance(tmp_path, monkeypatch):
    """Exercise the real coordinator against its real current-state adapter."""
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    delivery = fixture["delivery"]
    scenario = fixture["scenario"]
    # The fixture enriches the delivery authority with the accepted owner,
    # MAPIT-publication and historical-lineage receipts after the generic
    # delivery harness has been built. Reconstruct the real coordinator from
    # that final authority instead of reusing the harness's intentionally
    # earlier snapshot.
    from scripts.dev_owner_enrolled_delivery import OwnerEnrolledClosedDelivery
    from test_dev_owner_enrolled_delivery import Journal, _accepted

    artifact_journal, update_journal = Journal(), Journal()
    coordinator = OwnerEnrolledClosedDelivery(
        authority=delivery.auth,
        accepted=_accepted(delivery.auth),
        prior_template=delivery.prior,
        mapit_bootstrap_template=fixture["mapit_plan"].template,
        manifest_raw=delivery.args["manifest_raw"],
        invitation_jwks=delivery.args["invitation_jwks"],
        mapit_jwks=delivery.args["mapit_jwks"],
        archive_bytes=delivery.archive,
        archive_summary=delivery.summary,
        artifact_journal=artifact_journal,
        update_journal=update_journal,
        source_check=delivery.source_check,
        protection_check=delivery.protection_check,
        current_state=fixture["current"],
        publish_once=delivery.publish,
        update_once=delivery.update,
        clock=delivery.clock,
        monotonic=delivery.monotonic_clock,
    )
    delivery.coordinator = coordinator
    observed_phases = []

    def current_state(phase, binding):
        observed_phases.append(phase)
        return fixture["current"](phase, binding)

    coordinator._current_state = current_state
    assert coordinator.preflight() == {"ok": True, "phase": "ready"}
    assert delivery.publish_calls == delivery.update_calls == 0
    assert coordinator.publish()["phase"] == "published"
    assert delivery.publish_calls == 1 and delivery.update_calls == 0
    assert coordinator.update()["phase"] == "acknowledged"
    assert delivery.publish_calls == delivery.update_calls == 1
    scenario.phase = "accepted"
    accepted = coordinator.readback()

    assert accepted["phase"] == "accepted"
    assert accepted["resource_count"] == 19
    assert accepted["api_disabled"] is True
    assert accepted["lambda_reserved_concurrency"] == 0
    assert observed_phases == ["preflight", "pre_publish", "pre_publish",
                               "pre_update", "pre_update", "accepted"]
    assert delivery.publish_calls == delivery.update_calls == 1
    assert artifact_journal.state["phase"] == "published"
    assert update_journal.state["phase"] == "accepted"


@pytest.mark.parametrize("mutation", ["missing", "extra", "size", "token"])
def test_current_state_rejects_noncanonical_delivery_binding_before_sdk(tmp_path, monkeypatch, mutation):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    from pathlib import Path
    import scripts.dev_identity_binding_runtime_evidence as legacy
    from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError

    monkeypatch.setattr(legacy, "validate_private_location", lambda path: Path(path))
    scenario = fixture["scenario"]
    binding = dict(fixture["current"].delivery_binding)
    if mutation == "missing":
        binding.pop("client_request_token")
    elif mutation == "extra":
        binding["unexpected"] = True
    elif mutation == "size":
        binding["artifact_size"] += 1
    else:
        binding["client_request_token"] = "owner-enrolled-foreign"
    scenario.calls.clear()

    with pytest.raises(OwnerEnrolledReadbackError):
        fixture["current"]("preflight", binding)
    assert scenario.calls == []


def test_nested_sdk_ordered_mappings_normalize_without_mutation():
    from collections import OrderedDict
    from scripts.dev_owner_enrolled_runtime_readback import _json_document

    raw = OrderedDict(Metadata=OrderedDict(ManifestContract=OrderedDict(
        tenants=[OrderedDict(key="synthetic", label="A")])))
    result = _json_document(raw)
    assert type(result) is dict
    assert type(result["Metadata"]) is dict
    assert type(result["Metadata"]["ManifestContract"]["tenants"][0]) is dict
    assert type(raw["Metadata"]) is OrderedDict
    assert result == raw


@pytest.mark.parametrize("value", [
    {"Metadata": {1: "not-a-json-key"}},
    {"Metadata": ("not-a-json-array",)},
    {"Metadata": float("nan")},
    {"Metadata": float("inf")},
    {"Metadata": "x" * (64 * 1024)},
    '{"Metadata": NaN}',
    '{"Metadata": {}, "Metadata": {}}',
])
def test_sdk_document_normalization_rejects_non_json_or_oversized_values(value):
    from scripts.dev_owner_enrolled_runtime_readback import _json_document

    assert _json_document(value) is None
