"""Readonly acceptance of one owner MAPIT enrollment, with DEV still closed.

The historical delivery observer deliberately requires an empty namespace.
This separate observer accepts exactly the new owner's active version-one
session. It neither grants publication authority nor renews delivery receipts.
"""
from __future__ import annotations

from datetime import datetime
import math
import re
import time

from cryptography.hazmat.primitives import serialization

from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from mapit.durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from mapit.identity_binding import TenantIdentityBinding
from mapit.tenant_router import AuthenticatedTenant, InvitedTenantAuthority
from scripts.dev_owner_enrolled_accepted_inputs import AcceptedDeliveryInputs
from scripts.dev_owner_mapit_private_baseline import AcceptedPrivateBaseline
from scripts.dev_owner_enrolled_delivery_sdk import _is_registered_client_bundle
from scripts.dev_owner_enrolled_observation import sha256_json
from scripts.dev_mapit_bootstrap_contract import build_plan
from scripts.run_dev_mapit_binding_key_setup import _verify_retained_namespace_resources
from scripts.dev_owner_enrolled_runtime_readback import (
    _ClientsView, _ReadBudget, _json_document, _read_tenant_row,
    _stack_and_resources, _verify_api_and_lambda, _verify_authorization_table,
    _verify_owner_row, _verify_role,
)

_HANDLER = "honda-mapit-mcp-dev-retained-handler"
_ROLE = "honda-mapit-mcp-dev-retained-handler-role"
_SYNTHETIC_POLICY = "honda-mapit-mcp-dev-identity-bindings-runtime-read"
_NAMESPACE = "honda-mapit-mcp-dev-mapit-identity-bindings"


class OwnerMapitEnrollmentReadbackError(ValueError):
    def __init__(self):
        super().__init__("owner_mapit_enrollment_readback_unverified")


class _PostBudget(_ReadBudget):
    def __init__(self, *, deadline, before_sdk_call, **kwargs):
        self.deadline, self.before_sdk_call = deadline, before_sdk_call
        super().__init__(**kwargs)

    def check(self):
        super().check()
        if self.last >= self.deadline:
            raise OwnerMapitEnrollmentReadbackError()

    def call(self, service, method, **kwargs):
        self.check()
        self.before_sdk_call()
        return super().call(service, method, **kwargs)

    def confirm_session_absent(self, path):
        """An exact nondecrypted GET, accepting only the modeled 400 absence."""
        self.check()
        self.before_sdk_call()
        if self.calls >= self.max_calls:
            raise ValueError
        self.calls += 1
        try:
            self.clients["ssm"].get_parameter(Name=path, WithDecryption=False)
        except Exception as exc:
            self.check()
            reply = getattr(exc, "response", None)
            if (type(reply) is not dict or type(reply.get("Error")) is not dict
                    or reply["Error"].get("Code") != "ParameterNotFound"
                    or type(reply.get("ResponseMetadata")) is not dict
                    or type(reply["ResponseMetadata"].get("HTTPStatusCode")) is not int
                    or reply["ResponseMetadata"]["HTTPStatusCode"] != 400):
                raise ValueError from None
            return
        self.check()
        raise ValueError


def _parameter_metadata(reply, *, path, account, start, end):
    p = reply.get("Parameter")
    modified = p.get("LastModifiedDate") if type(p) is dict else None
    if (type(p) is not dict or p.get("Name") != path
            or p.get("ARN") != f"arn:aws:ssm:eu-west-1:{account}:parameter{path}"
            or p.get("Type") != "SecureString" or p.get("DataType") != "text"
            or type(p.get("Version")) is not int or p["Version"] != 1
            or not isinstance(modified, datetime) or modified.tzinfo is None
            or not start <= modified.timestamp() < end
            or "SourceResult" in p or p.get("Selector") not in (None, "")):
        raise OwnerMapitEnrollmentReadbackError()


def _public_keys_match(actual, expected):
    if set(actual) != set(expected):
        return False
    return all(actual[kid].public_numbers() == serialization.load_pem_public_key(
        expected[kid]).public_numbers() for kid in expected)


def _publication_metadata(view, *, path, account, key_arn, session, start, end):
    reply = view["ssm"].describe_parameters(ParameterFilters=[{
        "Key": "Name", "Option": "Equals", "Values": [path]}], MaxResults=5)
    rows = reply.get("Parameters")
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError
    p = rows[0]
    stamp = p.get("LastModifiedDate")
    if (p.get("Name") != path or p.get("Type") != "SecureString"
            or type(p.get("Version")) is not int or p["Version"] != 1
            or p.get("Tier") != "Standard" or p.get("DataType") != "text"
            or ("ARN" in p and p["ARN"] != f"arn:aws:ssm:eu-west-1:{account}:parameter{path}")
            or p.get("KeyId") not in {"alias/aws/ssm", key_arn, key_arn.rsplit("/", 1)[-1]}
            or p.get("LastModifiedUser") != f"arn:aws:sts::{account}:assumed-role/"
                f"honda-mapit-mcp-dev-mapit-enroller/{session}"
            or not isinstance(stamp, datetime) or stamp.tzinfo is None
            or not start <= stamp.timestamp() < end or p.get("Policies") not in (None, [])):
        raise ValueError


def verify_owner_mapit_enrollment(*, operation_id, grant, snapshot, binding,
        registry, authority, client_bundle, delivery_evidence,
        readonly_registry_factory, before_sdk_call, deadline,
        private_baseline=None, clock=time.time, monotonic=time.monotonic):
    """Verify current infrastructure and the exact post-enrollment delta.

    The caller has just rechecked source/protections and owns a fresh enrollment
    intent. ``before_sdk_call`` is its shared counter/time guard. The registry
    factory creates a new readonly lease with counted clients; the completed
    enrollment registry's old fourteen-second lease is never extended.
    No decrypted session or binding key is returned or persisted here.
    """
    try:
        def private_inputs_unchanged():
            if private_baseline is None:
                return delivery_evidence.assert_unchanged() is True
            return (type(private_baseline) is AcceptedPrivateBaseline
                and private_baseline.evidence is delivery_evidence
                and private_baseline.is_registered_native() is True)
        now, mono = clock(), monotonic()
        if (any(type(v) not in (int, float) or not math.isfinite(v)
                for v in (now, mono, deadline))
                or not 0 <= mono < deadline <= mono + 120
                or type(operation_id) is not str
                or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None
                or type(authority) is not dict or authority.get("operation_id") != operation_id
                or authority.get("kind") != "owner-mapit-enrollment-dev"
                or type(authority.get("schema")) is not int or authority["schema"] != 1
                or type(delivery_evidence) is not AcceptedDeliveryInputs
                or not private_inputs_unchanged()
                or _is_registered_client_bundle(client_bundle) is not True
                or type(grant) is not AuthenticatedTenant
                or type(snapshot) is not DurableTenantSnapshot
                or type(binding) is not TenantIdentityBinding
                or type(registry) is not DynamoDBIdentityBindingRegistry
                or not all(callable(v) for v in (readonly_registry_factory, before_sdk_call))):
            raise ValueError
        a = delivery_evidence.authority
        owner = a["owner_tenant_key"]
        path = f"/honda-mapit-mcp/dev/tenants/{owner}/mapit-refresh-token"
        manifest = parse_enrolled_dev_manifest(delivery_evidence.manifest_raw,
            delivery_evidence.invitation_jwks, delivery_evidence.mapit_jwks,
            expected_digest=a["manifest_sha256"], account_id=a["account_id"])
        start, end = authority["authorized_from_epoch"], authority["authorized_until_epoch"]
        if (type(start) is not int or type(end) is not int
                or not 0 < end - start <= 1200 or not start <= now < end
                or type(grant.expires_at) is not int or now >= grant.expires_at
                or authority.get("account_id") != a["account_id"]
                or authority.get("operator_arn") != a["operator_arn"]
                or authority.get("owner_tenant_key") != owner
                or authority.get("runtime_evidence_sha256") != delivery_evidence.update_state[
                    "receipt"]["runtime_evidence_sha256"]
                or grant.key != owner or binding.tenant_key != owner
                or binding.environment != "dev" or binding.secret_path != path
                or type(binding.secret_version) is not int or binding.secret_version != 1
                or type(binding.revision) is not int or binding.revision != 3
                or registry._namespace != "mapit"
                or registry._environment != "dev" or registry._account_id != a["account_id"]
                or registry._table_arn != f"arn:aws:dynamodb:eu-west-1:{a['account_id']}:table/{_NAMESPACE}"
                or registry.config != manifest.config or registry.verifier.config is not registry.config):
            raise ValueError
        if not _public_keys_match(registry.verifier._keys, manifest.mapit_keys):
            raise ValueError
        # Both objects were minted by the runner from the accepted manifest.
        invited, guard = registry._authority, registry._durable_guard
        if (type(invited) is not InvitedTenantAuthority or type(guard) is not DurableTenantGuard
                or not registry.is_bound_to(invited, guard) or not guard.is_bound_to(invited)
                or not invited.matches_environment("dev")
                or set(invited._policies) != {owner}
                or invited._policies[owner].owner_subject != manifest.policies[owner].owner_subject
                or not invited.matches_token_policy(manifest.policies[owner])):
            raise ValueError
        if not _public_keys_match(invited._verifiers[owner]._keys, manifest.invitation_keys):
            raise ValueError
        invited.validate(grant)
        guard.check(grant, snapshot)
        deadline = min(deadline, mono + grant.expires_at - now)
        budget = _PostBudget(authority=a, observation_window=authority,
            clock=clock, monotonic=monotonic, max_calls=80, deadline=deadline,
            before_sdk_call=before_sdk_call)
        budget.clients = client_bundle.clients
        view = _ClientsView(budget, budget.clients)
        identity = view["sts"].get_caller_identity()
        if identity.get("Account") != a["account_id"] or identity.get("Arn") != a["operator_arn"]:
            raise ValueError
        target = delivery_evidence.target_template
        _, rows = _stack_and_resources(view, a, target)
        progress = delivery_evidence.capsule["progress"]
        if {k: v["PhysicalResourceId"] for k, v in rows.items()} != progress["resource_ids"]:
            raise ValueError
        original = delivery_evidence.private_inputs
        table_id = _verify_authorization_table(view, a, target, rows,
            expected_run_id=original.runtime_binding["app_run_id"])
        if table_id != progress["authorization_table_id"]:
            raise ValueError
        _verify_api_and_lambda(view, a, target, rows,
            delivery_evidence.update_state["receipt"]["artifact_sha256"], accepted=True)
        _verify_owner_row(view, a)
        for index, key in enumerate(a["historical_tenant_keys"]):
            historical = _read_tenant_row(view, key)
            if sha256_json(historical) != progress["historical_row_sha256"][
                    "tenant_a" if index == 0 else "tenant_b"]:
                raise ValueError
        historical_policy = view["iam"].get_role_policy(RoleName=_ROLE, PolicyName=_SYNTHETIC_POLICY)
        policy = _json_document(historical_policy.get("PolicyDocument"))
        if (historical_policy.get("RoleName") != _ROLE
                or historical_policy.get("PolicyName") != _SYNTHETIC_POLICY
                or policy is None or sha256_json(policy) != progress["synthetic_policy_sha256"]):
            raise ValueError
        role_target = dict(target)
        role_target["__mapit_runtime_policy"] = original.bootstrap_template[
            "Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
        _verify_role(view, a, role_target, rows, accepted=True, synthetic_policy=policy)
        # Reuse complete retained namespace/table/IAM/KMS invariants. The
        # historical wrapper still requires absence; this observer records an
        # actual nonempty document and later verifies its MAC and active state.
        observed_item = []
        def observe_enrolled_document(reply):
            if (set(reply) != {"Item", "ResponseMetadata"}
                    or type(reply["Item"]) is not dict):
                raise ValueError
            observed_item.append(sha256_json(reply["Item"]))
        manifest_inputs = original.manifest_inputs
        bootstrap_authority = manifest_inputs["bootstrap_authority"]
        bootstrap_plan = build_plan(bootstrap_authority)
        if bootstrap_plan.template != original.bootstrap_template:
            raise ValueError
        _verify_retained_namespace_resources(
            {name: view[name] for name in budget.clients},
            bootstrap_authority, manifest_inputs["bootstrap_state"], bootstrap_plan,
            a["mapit_bootstrap_receipt_sha256"], [budget.calls], budget.started,
            deadline, monotonic, binding_document_check=observe_enrolled_document)
        if len(observed_item) != 1:
            raise ValueError
        published = original.manifest_inputs["publication"]
        _publication_metadata(view, path=a["mapit_config_path"], account=a["account_id"],
            key_arn=bootstrap_authority.ssm_key_arn, session=f"mapit-key-{published['run_id']}",
            start=published["start"], end=published["end"])
        _publication_metadata(view, path=path, account=a["account_id"],
            key_arn=bootstrap_authority.ssm_key_arn, session=f"owner-mapit-{operation_id}",
            start=start, end=end)
        _parameter_metadata(view["ssm"].get_parameter(Name=a["mapit_config_path"], WithDecryption=False),
            path=a["mapit_config_path"], account=a["account_id"],
            start=published["start"], end=published["end"])
        _parameter_metadata(view["ssm"].get_parameter(Name=path, WithDecryption=False),
            path=path, account=a["account_id"], start=start, end=end)
        for other in bootstrap_authority._tenant_keys:
            if other == owner:
                continue
            budget.confirm_session_absent(
                f"/honda-mapit-mcp/dev/tenants/{other}/mapit-refresh-token")
        # Start the new registry lease only after infrastructure reads. It is
        # readonly, uses the same accepted authority/verifier and cannot retry
        # any enrollment write. Exact document cardinality rejects extra users.
        budget.check()
        table_arn = f"arn:aws:dynamodb:eu-west-1:{a['account_id']}:table/{_NAMESPACE}"
        final_document = view["dynamodb"].get_item(TableName=table_arn,
            Key={"key": {"S": "identity-bindings-v1"}}, ConsistentRead=True,
            ReturnConsumedCapacity="NONE")
        if (set(final_document) != {"Item", "ResponseMetadata"}
                or sha256_json(final_document["Item"]) != observed_item[0]):
            raise ValueError
        readonly = readonly_registry_factory(deadline=min(deadline, monotonic() + 14))
        if (type(readonly) is not DynamoDBIdentityBindingRegistry
                or readonly._writer is not None or readonly._namespace != "mapit"
                or not readonly.is_bound_to(invited, guard)
                or readonly.config is not registry.config or readonly.verifier is not registry.verifier
                or readonly._table_arn != registry._table_arn):
            raise ValueError
        revision, records = readonly._read_document()
        if type(revision) is not int or revision != 3 or set(records) != {owner}:
            raise ValueError
        readonly.validate_binding(grant, snapshot, binding)
        guard.check(grant, snapshot)
        api_id = original.manifest_inputs["context"].policy.api_id
        api = view["apigatewayv2"].get_api(ApiId=api_id)
        reserve = view["lambda"].get_function_concurrency(FunctionName=_HANDLER)
        identity = view["sts"].get_caller_identity()
        if (api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
                or type(reserve.get("ReservedConcurrentExecutions")) is not int
                or reserve["ReservedConcurrentExecutions"] != 0
                or identity.get("Account") != a["account_id"] or identity.get("Arn") != a["operator_arn"]):
            raise ValueError
        budget.check()
        if not private_inputs_unchanged():
            raise ValueError
        budget.check()
        return {"schema": 1, "kind": "owner-mapit-enrollment-closed-readback",
            "operation_id": operation_id, "owner_key": owner,
            "secret_version": 1, "binding_revision": 3, "closed": True, "reservation": 0}
    except Exception:
        raise OwnerMapitEnrollmentReadbackError() from None
