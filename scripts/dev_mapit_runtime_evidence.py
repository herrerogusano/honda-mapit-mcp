"""Read-only current-runtime evidence for the distinct DEV MAPIT namespace.

The legacy runtime verifier remains unchanged. This adapter validates the full
three/four-policy handler inventory, projects only the already-validated
legacy inventory to that verifier, and binds the result to a private evidence
bundle. It does not construct clients or perform writes.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Callable

from scripts.aws_dev_identity_binding_bootstrap import DevIdentityBindingBootstrapCoordinator
from scripts.build_aws_dev_identity_binding_bootstrap import (
    build_dev_identity_binding_bootstrap,
)
from scripts.dev_identity_binding_runtime_evidence import (
    ROLE as HANDLER_ROLE,
    _resolve_context,
    verify_accepted_runtime,
)
from scripts.dev_mapit_bootstrap_contract import (
    MapitBootstrapAuthority,
    MapitBootstrapContractError,
    build_plan,
)
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_retained_dev_bootstrap import validate_private_location
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _COORDINATOR_FIELDS,
    load_authorization,
    load_binding,
)

_BUNDLE_KIND = "dev-mapit-runtime-evidence"
_BUNDLE_FIELDS = frozenset({
    "schema", "kind", "account_id", "caller_arn", "source_sha", "run_id",
    "authorized_from_epoch", "authorized_until_epoch", "mapit_plan_sha256",
    "synthetic_binding_sha256", "synthetic_authorization_sha256",
    "synthetic_state_sha256", "runtime_binding",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BUNDLE_BYTES = 64 * 1024
_MAX_STATE_BYTES = 128 * 1024
_BASELINE_POLICIES = frozenset({
    "honda-mapit-mcp-dev-retained-owned-log-writes",
    "honda-mapit-mcp-dev-retained-tenant-read",
})
_READ_PREFIXES = ("get_", "describe_", "list_")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def _decode_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def runtime_evidence_digest(bundle: Mapping[str, Any]) -> str:
    """Digest the complete bundle, including paths-independent provenance."""
    if not isinstance(bundle, Mapping):
        raise ValueError("evidence_invalid")
    return _digest(dict(bundle))


class _EvidenceFailure(Exception):
    pass


class _CountingClient:
    def __init__(self, service: str, client: Any, counter: list[int], deadline: float,
                 monotonic: Callable[[], float], clock_state: list[float]):
        self._service, self._client, self._counter = service, client, counter
        self._deadline, self._monotonic = deadline, monotonic
        self._clock_state = clock_state

    def __getattr__(self, operation: str) -> Any:
        if not operation.startswith(_READ_PREFIXES):
            raise _EvidenceFailure
        target = getattr(self._client, operation, None)
        if not callable(target):
            raise _EvidenceFailure

        def read(**kwargs: Any) -> Any:
            now = self._monotonic()
            if (type(now) not in (int, float) or isinstance(now, bool)
                    or not math.isfinite(now) or now < self._clock_state[0] or now >= self._deadline):
                raise _EvidenceFailure
            if self._counter[0] >= 64:
                raise _EvidenceFailure
            self._counter[0] += 1
            result = target(**kwargs)
            now_after = self._monotonic()
            if (type(now_after) not in (int, float) or isinstance(now_after, bool)
                    or not math.isfinite(now_after) or now_after < now or now_after < self._clock_state[0]
                    or now_after >= self._deadline):
                raise _EvidenceFailure
            self._clock_state[0] = float(now_after)
            if not _valid_reply(result):
                raise _EvidenceFailure
            return result
        return read


def _valid_reply(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    metadata = value.get("ResponseMetadata")
    if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
            or metadata["HTTPStatusCode"] != 200):
        return False
    for key in ("NextToken", "NextMarker", "Marker"):
        if value.get(key) not in (None, ""):
            return False
    if "IsTruncated" in value and (type(value["IsTruncated"]) is not bool or value["IsTruncated"]):
        return False
    return True


def _read_private(path: Path, *, acl_checker: Callable[[Path], bool] | None,
                  maximum: int) -> tuple[Path, bytes]:
    resolved = validate_private_location(path, acl_checker=acl_checker)
    if not resolved.is_file():
        raise _EvidenceFailure
    size = resolved.stat().st_size
    if type(size) is not int or size <= 0 or size > maximum:
        raise _EvidenceFailure
    raw = resolved.read_bytes()
    if len(raw) != size or len(raw) > maximum:
        raise _EvidenceFailure
    return resolved, raw


def _load_bundle(path: Path, *, acl_checker: Callable[[Path], bool] | None) -> tuple[dict[str, Any], bytes]:
    _, raw = _read_private(path, acl_checker=acl_checker, maximum=_MAX_BUNDLE_BYTES)
    value = _decode_json(raw)
    if type(value) is not dict or set(value) != _BUNDLE_FIELDS:
        raise _EvidenceFailure
    return value, raw


def _validate_bundle(bundle: Mapping[str, Any], authority: MapitBootstrapAuthority,
                     expected_template: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if (type(bundle.get("schema")) is not int or bundle["schema"] != 1
                or bundle.get("kind") != _BUNDLE_KIND
                or bundle.get("account_id") != authority.account_id
                or bundle.get("caller_arn") != authority.expected_caller_arn
                or bundle.get("source_sha") != authority.source_sha
                or type(bundle.get("run_id")) is not int or bundle["run_id"] != authority.run_id
                or type(bundle.get("authorized_from_epoch")) is not int
                or bundle["authorized_from_epoch"] != authority.authorized_from_epoch
                or type(bundle.get("authorized_until_epoch")) is not int
                or bundle["authorized_until_epoch"] != authority.authorized_until_epoch
                or type(bundle.get("mapit_plan_sha256")) is not str
                or bundle["mapit_plan_sha256"] != _digest(expected_template)):
            raise _EvidenceFailure
        for key in ("synthetic_binding_sha256", "synthetic_authorization_sha256", "synthetic_state_sha256"):
            if type(bundle.get(key)) is not str or _SHA256.fullmatch(bundle[key]) is None:
                raise _EvidenceFailure
        runtime = bundle.get("runtime_binding")
        if not isinstance(runtime, Mapping):
            raise _EvidenceFailure
        from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS
        if set(runtime) != set(_BINDING_FIELDS):
            raise _EvidenceFailure
        runtime = dict(runtime)
        tenant_keys = runtime.get("tenant_keys")
        if (type(tenant_keys) is not list or len(tenant_keys) != 2
                or any(type(key) is not str for key in tenant_keys)):
            raise _EvidenceFailure
        runtime["tenant_keys"] = tuple(tenant_keys)
        # These exact owner/runtime fields are independently validated by the
        # legacy verifier, and are also tied here to the fresh authority.
        required = {
            "account_id": authority.account_id,
            "operator_user_arn": authority.expected_caller_arn,
            "app_stack_arn": f"arn:aws:cloudformation:eu-west-1:{authority.account_id}:stack/honda-mapit-mcp-dev-retained/",
        }
        if (runtime.get("account_id") != required["account_id"]
                or runtime.get("operator_user_arn") != required["operator_user_arn"]
                or type(runtime.get("app_stack_arn")) is not str
                or re.fullmatch(re.escape(required["app_stack_arn"]) + r"[0-9a-f-]{36}", runtime["app_stack_arn"]) is None):
            raise _EvidenceFailure
        return dict(runtime)
    except _EvidenceFailure:
        raise
    except Exception:
        raise _EvidenceFailure from None


def _validate_historical_bootstrap(*, clients: Mapping[str, Any],
                                   binding_path: Path, authorization_path: Path,
                                   state_dir: Path, bundle: Mapping[str, Any],
                                   authority: MapitBootstrapAuthority,
                                   acl_checker: Callable[[Path], bool] | None) -> dict[str, Any]:
    # Strict existing parsers; this is a read-only provenance check.
    binding = load_binding(binding_path, acl_checker=acl_checker)
    authorization = load_authorization(validate_private_location(authorization_path, acl_checker=acl_checker))
    _, binding_bytes = _read_private(binding_path, acl_checker=acl_checker, maximum=32 * 1024)
    _, auth_bytes = _read_private(authorization_path, acl_checker=acl_checker, maximum=32 * 1024)
    raw_binding = _decode_json(binding_bytes)
    if type(raw_binding) is not dict or type(raw_binding.get("tenant_keys")) is not list:
        raise _EvidenceFailure
    raw_binding["tenant_keys"] = tuple(raw_binding["tenant_keys"])
    if raw_binding != binding or _decode_json(auth_bytes) != authorization:
        raise _EvidenceFailure
    if (hashlib.sha256(binding_bytes).hexdigest() != bundle["synthetic_binding_sha256"]
            or hashlib.sha256(auth_bytes).hexdigest() != bundle["synthetic_authorization_sha256"]):
        raise _EvidenceFailure
    private_state_dir = validate_private_location(state_dir, acl_checker=acl_checker)
    state_path = private_state_dir / "rehearsal-state.json"
    journal = FileJournal(private_state_dir)
    _, state_bytes = _read_private(state_path, acl_checker=acl_checker, maximum=_MAX_STATE_BYTES)
    if hashlib.sha256(state_bytes).hexdigest() != bundle["synthetic_state_sha256"]:
        raise _EvidenceFailure
    old_journal = journal.load()
    if not isinstance(old_journal, Mapping):
        raise _EvidenceFailure
    if _decode_json(state_bytes) != dict(old_journal):
        raise _EvidenceFailure
    source = old_journal.get("source_sha")
    run_id = old_journal.get("run_id")
    caller = old_journal.get("expected_caller_arn")
    start = old_journal.get("authorized_from_epoch")
    end = old_journal.get("authorized_until_epoch")
    if (type(source) is not str or re.fullmatch(r"[0-9a-f]{40}", source) is None
            or type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0
            or type(caller) is not str or type(start) is not int or isinstance(start, bool)
            or type(end) is not int or isinstance(end, bool)):
        raise _EvidenceFailure
    authorization_matches = (
        authorization.get("account") == binding["account_id"]
        and authorization.get("source_sha") == source
        and authorization.get("run_id") == run_id
        and authorization.get("expected_caller_arn") == caller
        and authorization.get("start") == start and authorization.get("end") == end
        and caller == authority.expected_caller_arn
    )
    if not authorization_matches:
        raise _EvidenceFailure
    coordinator = DevIdentityBindingBootstrapCoordinator(
        clients, journal, binding={key: binding[key] for key in _COORDINATOR_FIELDS},
        source_sha=source, run_id=run_id, expected_caller_arn=caller,
        authorized_from_epoch=start, authorized_until_epoch=end,
        accepted_runtime_verifier=lambda *_a, **_k: {},
    )
    loaded = coordinator._load()  # read-only parser; never call run_step.
    if (loaded is None or loaded.get("preflight") is not True
            or loaded.get("acknowledged") is not True or loaded.get("readback") is not True
            or loaded.get("intent") is None):
        raise _EvidenceFailure
    if (binding["account_id"] != authority.account_id
            or binding["operator_user_arn"] != authority.expected_caller_arn
            or set(binding["tenant_keys"]) & set(authority._tenant_keys)
            or binding["app_stack_arn"] != bundle["runtime_binding"]["app_stack_arn"]
            or binding["api_id"] != bundle["runtime_binding"]["api_id"]
            or binding["handler_role_arn"] != bundle["runtime_binding"]["handler_role_arn"]):
        raise _EvidenceFailure
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=binding["account_id"], operator_user_arn=binding["operator_user_arn"],
        tenant_keys=binding["tenant_keys"], ssm_key_arn=binding["ssm_key_arn"],
    )
    if (loaded.get("template_sha256") != coordinator.template_sha256
            or coordinator.template_sha256 != _digest(synthetic)):
        raise _EvidenceFailure
    policy = synthetic["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    return {"policy_name": policy["PolicyName"], "policy_document": policy["PolicyDocument"]}


class _ProjectedIAM:
    """Expose an already-validated three-policy view to the frozen verifier."""
    def __init__(self, snapshot: Mapping[str, Any]):
        self.snapshot = snapshot

    def get_role(self, **kwargs: Any) -> Mapping[str, Any]:
        return self.snapshot["role_reply"]

    def list_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        return {"PolicyNames": list(self.snapshot["projected_names"]),
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_role_policy(self, *, RoleName: str, PolicyName: str) -> Mapping[str, Any]:
        if PolicyName not in self.snapshot["projected_policies"]:
            raise _EvidenceFailure
        return {"RoleName": RoleName, "PolicyName": PolicyName,
                "PolicyDocument": self.snapshot["projected_policies"][PolicyName],
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_attached_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        return self.snapshot["attached_reply"]


class _ProjectionClient:
    def __init__(self, iam: _ProjectedIAM):
        self._iam = iam

    def __getattr__(self, name: str) -> Any:
        return getattr(self._iam, name)


def _policy_snapshot(iam: Any, *, expected_template: Mapping[str, Any], resource_rows: Mapping[str, Any], account: str,
                     phase: str, mapit_template: Mapping[str, Any]) -> dict[str, Any]:
    reader = iam
    resources = expected_template["Resources"]
    role_props = resources["McpHandlerRole"]["Properties"]
    role_name = HANDLER_ROLE
    expected_role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    role_reply = reader.get_role(RoleName=role_name)
    role = role_reply.get("Role") if isinstance(role_reply, Mapping) else None
    if not isinstance(role, Mapping) or role.get("Arn") != expected_role_arn or role.get("PermissionsBoundary") is not None:
        raise _EvidenceFailure
    from scripts.aws_dev_identity_binding_bootstrap import _document as decode_document
    trust = decode_document(role.get("AssumeRolePolicyDocument"))
    expected_trust = _resolve_context(role_props["AssumeRolePolicyDocument"], account=account,
                                      resource_rows={})
    if trust != expected_trust:
        raise _EvidenceFailure
    names_reply = reader.list_role_policies(RoleName=role_name)
    names = names_reply.get("PolicyNames") if isinstance(names_reply, Mapping) else None
    if (type(names) is not list or len(names) != len(set(names))
            or any(type(name) is not str for name in names)):
        raise _EvidenceFailure
    expected_base = {item["PolicyName"]: _resolve_context(item["PolicyDocument"], account=account,
                                                         resource_rows=resource_rows)
                     for item in role_props["Policies"]}
    # Synthetic policy is separately validated from the frozen factory and
    # supplied through the temporary field attached by the caller.
    synthetic = mapit_template.get("__synthetic_policy")
    if not isinstance(synthetic, Mapping):
        raise _EvidenceFailure
    expected_policies = dict(expected_base)
    expected_policies[synthetic["policy_name"]] = synthetic["policy_document"]
    expected_mapit = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    if expected_mapit.get("Roles") != [HANDLER_ROLE]:
        raise _EvidenceFailure
    mapit_policy_name = expected_mapit["PolicyName"]
    expected_policies[mapit_policy_name] = _resolve_context(expected_mapit["PolicyDocument"],
                                                            account=account, resource_rows=resource_rows)
    expected_names = set(expected_policies)
    names_set = set(names)
    if names_set not in (expected_names - {mapit_policy_name}, expected_names):
        raise _EvidenceFailure
    if (phase == "readback") != (mapit_policy_name in names_set):
        raise _EvidenceFailure
    policies: dict[str, Any] = {}
    for name in sorted(names_set):
        reply = reader.get_role_policy(RoleName=role_name, PolicyName=name)
        if reply.get("RoleName") != role_name or reply.get("PolicyName") != name:
            raise _EvidenceFailure
        document = decode_document(reply.get("PolicyDocument"))
        if document is None or document != expected_policies[name]:
            raise _EvidenceFailure
        policies[name] = document
    attached = reader.list_attached_role_policies(RoleName=role_name)
    rows = attached.get("AttachedPolicies") if isinstance(attached, Mapping) else None
    if type(rows) is not list or rows:
        raise _EvidenceFailure
    baseline_snapshot = {
        "role_reply": role_reply,
        "projected_names": sorted(expected_base.keys() | {synthetic["policy_name"]}),
        "projected_policies": {name: policies[name] for name in expected_base.keys() | {synthetic["policy_name"]}},
        "attached_reply": attached,
        "full_names": tuple(sorted(names_set)),
        "full_policies": policies,
        "trust": trust,
    }
    return baseline_snapshot


def _assert_historical_keys_disjoint(snapshot: Mapping[str, Any], authority: MapitBootstrapAuthority) -> None:
    document = snapshot["projected_policies"]["honda-mapit-mcp-dev-retained-tenant-read"]
    statements = document.get("Statement")
    if type(statements) is not list or len(statements) != 1:
        raise _EvidenceFailure
    condition = statements[0].get("Condition")
    if (not isinstance(condition, Mapping) or set(condition) != {"ForAllValues:StringEquals"}
            or not isinstance(condition["ForAllValues:StringEquals"], Mapping)
            or set(condition["ForAllValues:StringEquals"]) != {"dynamodb:LeadingKeys"}):
        raise _EvidenceFailure
    keys = condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]
    if (type(keys) is not list or len(keys) != 2
            or any(type(key) is not str or re.fullmatch(r"tenant-[0-9a-f]{64}", key) is None for key in keys)
            or len(set(keys)) != 2 or set(keys).intersection(authority._tenant_keys)):
        raise _EvidenceFailure


def make_mapit_runtime_evidence_verifier(
    evidence_path: Path,
    *,
    synthetic_binding_path: Path,
    synthetic_authorization_path: Path,
    synthetic_state_dir: Path,
    acl_checker: Callable[[Path], bool] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> Callable[..., Mapping[str, Any]]:
    """Create the trusted read-only callback passed to MapitBootstrapCoordinator.

    The caller must supply private evidence created by a separate reviewed
    preparer. The digest binds the whole JSON bundle to the fresh authority.
    """
    for callback in (acl_checker, monotonic):
        if callback is not None and not callable(callback):
            raise ValueError("evidence_invalid")
    bundle_path = Path(evidence_path)
    binding_path = Path(synthetic_binding_path)
    authorization_path = Path(synthetic_authorization_path)
    state_dir = Path(synthetic_state_dir)

    def verify(clients: Mapping[str, Any], authority: MapitBootstrapAuthority,
               expected_mapit_template: Mapping[str, Any], *, phase: str) -> Mapping[str, Any]:
        counter = [0]
        started = monotonic()
        if (type(started) not in (int, float) or isinstance(started, bool)
                or not math.isfinite(started)):
            return _failure(phase, counter[0])
        deadline = float(started) + 25.0
        clock_state = [float(started)]
        try:
            if type(authority) is not MapitBootstrapAuthority or phase not in {"preflight", "create", "readback"}:
                raise _EvidenceFailure
            plan = build_plan(authority)
            if _digest(expected_mapit_template) != plan.template_sha256:
                raise _EvidenceFailure
            bundle, _raw = _load_bundle(bundle_path, acl_checker=acl_checker)
            if set(bundle) != _BUNDLE_FIELDS or _digest(bundle) != authority.runtime_evidence_sha256:
                raise _EvidenceFailure
            runtime_binding = _validate_bundle(bundle, authority, expected_mapit_template)
            if (not isinstance(clients, Mapping) or set(clients) != {
                    "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                    "apigatewayv2", "lambda", "kms"}):
                raise _EvidenceFailure
            synthetic_policy = _validate_historical_bootstrap(
                clients=clients, binding_path=binding_path, authorization_path=authorization_path,
                state_dir=state_dir, bundle=bundle, authority=authority, acl_checker=acl_checker,
            )
            # Bundle runtime identity/window must be exactly the fresh coordinator context.
            if (runtime_binding.get("account_id") != authority.account_id
                    or runtime_binding.get("operator_user_arn") != authority.expected_caller_arn
                    or type(runtime_binding.get("app_run_id")) is not int
                    or runtime_binding.get("app_run_id") <= 0):
                raise _EvidenceFailure
            counted = {name: _CountingClient(name, client, counter, deadline, monotonic, clock_state)
                       for name, client in clients.items()}
            _verify_caller(counted, authority)
            mapit_with_synthetic = dict(expected_mapit_template)
            mapit_with_synthetic["__synthetic_policy"] = synthetic_policy
            # Read the full actual role inventory twice; the legacy verifier gets
            # a cached projection so its three-policy contract remains unchanged.
            app_template, app_rows = _current_template(counted, runtime_binding)
            if _digest(app_template) != runtime_binding["template_sha256"]:
                raise _EvidenceFailure
            before = _policy_snapshot(counted["iam"], expected_template=app_template, resource_rows=app_rows,
                                     account=authority.account_id, phase=phase,
                                     mapit_template=mapit_with_synthetic)
            _assert_historical_keys_disjoint(before, authority)
            projection = _ProjectedIAM(before)
            legacy_clients = dict(counted)
            legacy_clients["iam"] = _ProjectionClient(projection)
            legacy_binding = dict(runtime_binding)
            legacy_binding["added_runtime_policy"] = synthetic_policy
            legacy_result = verify_accepted_runtime(legacy_clients, legacy_binding)
            if not isinstance(legacy_result, Mapping) or legacy_result.get("verified") is not True:
                raise _EvidenceFailure
            after_template, after_rows = _current_template(counted, runtime_binding)
            if _digest(after_template) != _digest(app_template) or _digest(after_rows) != _digest(app_rows):
                raise _EvidenceFailure
            after = _policy_snapshot(counted["iam"], expected_template=after_template, resource_rows=after_rows,
                                     account=authority.account_id, phase=phase,
                                     mapit_template=mapit_with_synthetic)
            if (before["full_names"] != after["full_names"]
                    or before["full_policies"] != after["full_policies"]
                    or before["trust"] != after["trust"]):
                raise _EvidenceFailure
            # Fresh closure reads after the full IAM reread.
            api = counted["apigatewayv2"].get_api(ApiId=runtime_binding["api_id"])
            if (api.get("ApiId") != runtime_binding["api_id"]
                    or api.get("DisableExecuteApiEndpoint") is not True):
                raise _EvidenceFailure
            concurrency = counted["lambda"].get_function_concurrency(FunctionName=HANDLER_ROLE.removesuffix("-role"))
            if type(concurrency.get("ReservedConcurrentExecutions")) is not int or concurrency["ReservedConcurrentExecutions"] != 0:
                raise _EvidenceFailure
            _verify_caller(counted, authority)
            now = monotonic()
            if (type(now) not in (int, float) or isinstance(now, bool)
                    or not math.isfinite(now) or now < clock_state[0] or now >= deadline or counter[0] > 64):
                raise _EvidenceFailure
            return {
                "verified": True, "calls": counter[0], "phase": phase,
                "account_id": authority.account_id, "source_sha": authority.source_sha,
                "run_id": authority.run_id, "caller_arn": authority.expected_caller_arn,
                "evidence_sha256": authority.runtime_evidence_sha256,
                "resource_count": 19, "api_closed": True, "reserve_zero": True,
                "mapit_policy_attached": phase == "readback",
            }
        except Exception:
            return _failure(phase, counter[0])
    return verify


def _current_template(clients: Mapping[str, Any], binding: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    # Used only to derive expected baseline policy documents; the legacy
    # verifier independently performs its own current-template read/hash.
    reply = clients["cloudformation"].get_template(StackName=binding["app_stack_arn"], TemplateStage="Original")
    body = reply.get("TemplateBody")
    if type(body) is str:
        template = json.loads(body, object_pairs_hook=_unique)
    elif isinstance(body, Mapping):
        template = dict(body)
    else:
        raise _EvidenceFailure
    if type(template) is not dict or len(template.get("Resources", {})) != 19:
        raise _EvidenceFailure
    reply = clients["cloudformation"].list_stack_resources(StackName=binding["app_stack_arn"])
    rows = reply.get("StackResourceSummaries")
    if type(rows) is not list or len(rows) != 19:
        raise _EvidenceFailure
    expected_types = {name: item.get("Type") for name, item in template["Resources"].items()}
    by_name: dict[str, Any] = {}
    for row in rows:
        if (not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str
                or row["LogicalResourceId"] in by_name
                or row.get("ResourceType") != expected_types.get(row["LogicalResourceId"])
                or row.get("ResourceStatus") != "CREATE_COMPLETE"
                and row.get("ResourceStatus") != "UPDATE_COMPLETE"):
            raise _EvidenceFailure
        by_name[row["LogicalResourceId"]] = dict(row)
    return template, by_name


def _verify_caller(clients: Mapping[str, Any], authority: MapitBootstrapAuthority) -> None:
    result = clients["sts"].get_caller_identity()
    if (result.get("Account") != authority.account_id
            or result.get("Arn") != authority.expected_caller_arn):
        raise _EvidenceFailure


def _failure(phase: Any, calls: int) -> dict[str, Any]:
    safe_phase = phase if type(phase) is str and phase in {"preflight", "create", "readback"} else "preflight"
    safe_calls = calls if type(calls) is int and 0 <= calls <= 64 else 0
    return {"verified": False, "calls": safe_calls, "phase": safe_phase,
            "account_id": "", "source_sha": "", "run_id": 0, "caller_arn": "",
            "evidence_sha256": "", "resource_count": 0, "api_closed": False,
            "reserve_zero": False, "mapit_policy_attached": False}


__all__ = ["make_mapit_runtime_evidence_verifier", "runtime_evidence_digest"]
