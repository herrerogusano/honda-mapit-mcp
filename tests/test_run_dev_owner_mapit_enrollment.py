from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import threading

import jwt
import pytest

from scripts import run_dev_owner_mapit_enrollment as runner

ACCOUNT = "123456789012"
KEY = "tenant-" + "a" * 64
NOW = 1_900_001_000
SOURCE = "d" * 40
ROLE = "arn:aws:iam::" + ACCOUNT + ":role/honda-mapit-mcp-dev-mapit-enroller"


def authority(evidence, **changes):
    value = {"schema": 1, "kind": "owner-mapit-enrollment-dev", "operation_id": "c" * 32,
        "account_id": ACCOUNT, "operator_arn": evidence.authority["operator_arn"],
        "source_sha": SOURCE, "ci_run_id": 999, "github_owner_id": 12, "github_repository_id": 34,
        "authorized_from_epoch": NOW - 1, "authorized_until_epoch": NOW + 599,
        "runtime_evidence_sha256": evidence.update_state["receipt"]["runtime_evidence_sha256"],
        "owner_tenant_key": evidence.authority["owner_tenant_key"], "max_sdk_calls": 192,
        "state_directory": str(Path("C:/synthetic-private-operation").resolve())}
    value.update(changes)
    return value


def evidence():
    return SimpleNamespace(authority={"account_id": ACCOUNT,
        "operator_arn": "arn:aws:iam::" + ACCOUNT + ":user/dev-operator",
        "github_owner_id": 12, "github_repository_id": 34, "owner_tenant_key": KEY},
        update_state={"receipt": {"runtime_evidence_sha256": "7" * 64}},
        binding={"owner_tenant_key": KEY}, assert_unchanged=lambda: True)


def operation(tmp_path, *, wall=None, mono=None, **changes):
    ev = evidence()
    root = tmp_path / "operation"
    root.mkdir()
    (root / "authorization.json").write_bytes(runner._canonical(authority(ev, state_directory=str(root.resolve()), **changes)))
    op = runner._Operation(root=root, evidence=ev, source_sha=SOURCE, ci_run_id=999,
        acl_checker=lambda _: True, clock=wall or (lambda: NOW), monotonic=mono or (lambda: 100))
    op.gates_verified()
    return op


@pytest.mark.parametrize("changes", [{"kind": "dev-owner-enrolled-delivery"}, {"schema": True},
    {"operation_id": "A" * 32}, {"account_id": "999999999999"},
    {"operator_arn": "arn:aws:iam::123456789012:root"}, {"source_sha": "e" * 40},
    {"ci_run_id": True}, {"github_owner_id": True}, {"github_repository_id": 35},
    {"authorized_until_epoch": NOW}, {"authorized_from_epoch": NOW + 1},
    {"authorized_until_epoch": NOW + 1200}, {"runtime_evidence_sha256": "0" * 64},
    {"owner_tenant_key": "tenant-" + "b" * 64}, {"max_sdk_calls": True}, {"max_sdk_calls": 193},
    {"unexpected": "private-canary"}])
def test_authority_crossing_or_expiry_is_denied_before_sdk(changes):
    ev = evidence()
    with pytest.raises(runner.OwnerMapitEnrollmentError, match="^owner_mapit_enrollment_unverified$"):
        runner.validate_enrollment_authority(authority(ev, **changes), evidence=ev,
            source_sha=SOURCE, ci_run_id=999, now=NOW, authority_root=Path("C:/synthetic-private-operation"))


@pytest.mark.parametrize("now", [True, -1, float("nan"), float("inf")])
def test_invalid_clocks_are_not_authority(now):
    ev = evidence()
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner.validate_enrollment_authority(authority(ev), evidence=ev, source_sha=SOURCE, ci_run_id=999, now=now,
            authority_root=Path("C:/synthetic-private-operation"))


def test_initial_clock_rollback_below_authority_start_creates_no_attempt(tmp_path):
    ev = evidence()
    root = tmp_path / "operation"
    root.mkdir()
    (root / "authorization.json").write_bytes(runner._canonical(authority(ev, state_directory=str(root.resolve()))))
    wall = iter([NOW, NOW - 2, NOW - 2])
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._Operation(root=root, evidence=ev, source_sha=SOURCE, ci_run_id=999,
            acl_checker=lambda _: True, clock=lambda: next(wall), monotonic=lambda: 100)
    assert not (root / "attempt.json").exists()


def test_owning_accepted_loader_and_history_are_immutable(tmp_path):
    from tests.test_dev_owner_enrolled_accepted_inputs import _accepted
    root, paths, _, _ = _accepted(tmp_path / "history")
    loaded = runner.load_accepted_owner_delivery(delivery_root=root, private_paths=paths, acl_checker=lambda _: True)
    frozen = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    now = loaded.authority["authorized_until_epoch"] + 10
    current = authority(loaded, authorized_from_epoch=now - 1, authorized_until_epoch=now + 599,
        state_directory=str(fresh.resolve()))
    (fresh / "authorization.json").write_bytes(runner._canonical(current))
    op = runner._Operation(root=fresh, evidence=loaded, source_sha=SOURCE, ci_run_id=999,
        acl_checker=lambda _: True, clock=lambda: now, monotonic=lambda: 100)
    op.gates_verified()
    op.intent()
    assert loaded.assert_unchanged() is True
    assert all(p.read_bytes() == raw for p, raw in frozen.items())
    assert {p.name for p in fresh.iterdir()} == {"authorization.json", "attempt.json", "intent.json"}


@pytest.mark.parametrize("which", ["authority", "attempt", "intent", "acl", "evidence"])
def test_private_drift_fails_before_write(tmp_path, which):
    op = operation(tmp_path)
    op.intent()
    calls = []
    client = SimpleNamespace(put_item=lambda **kw: calls.append(kw))
    if which in {"authority", "attempt", "intent"}:
        path = op.root / {"authority": "authorization.json", "attempt": "attempt.json", "intent": "intent.json"}[which]
        path.write_bytes(path.read_bytes() + b" ")
    elif which == "acl":
        op.acl_checker = lambda _: False
    else:
        op.evidence.assert_unchanged = lambda: False
    with pytest.raises(Exception):
        op.dispatch(client, "put_item", {}, deadline=114, write="ddb")
    assert calls == [] and op.ddb_writes == 0


def test_durable_and_process_repeat_fences_without_deleting_journal(tmp_path):
    op = operation(tmp_path)
    args = dict(root=op.root, evidence=op.evidence, source_sha=SOURCE, ci_run_id=999,
        acl_checker=lambda _: True, clock=lambda: NOW, monotonic=lambda: 100)
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._Operation(**args)
    # A fresh process would lack the registry; the durable attempt still fences it.
    runner._ATTEMPTED_ROOTS.discard(str(op.root).casefold())
    with pytest.raises(FileExistsError):
        runner._Operation(**args)
    assert (op.root / "attempt.json").exists()


def test_consumed_authority_cannot_be_copied_to_a_fresh_sibling_root(tmp_path):
    op = operation(tmp_path)
    sibling = tmp_path / "copied-operation"
    sibling.mkdir()
    (sibling / "authorization.json").write_bytes((op.root / "authorization.json").read_bytes())
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._Operation(root=sibling, evidence=op.evidence, source_sha=SOURCE, ci_run_id=999,
            acl_checker=lambda _: True, clock=lambda: NOW, monotonic=lambda: 100)
    assert not (sibling / "attempt.json").exists()


@pytest.mark.parametrize("which", ["wall_rollback", "mono_rollback", "wall_expiry", "mono_expiry", "stale", "deadline"])
def test_clock_and_fresh_source_fences_are_exclusive(tmp_path, which):
    wall, mono = [NOW], [100]
    op = operation(tmp_path, wall=lambda: wall[0], mono=lambda: mono[0])
    op.intent()
    if which == "wall_rollback": wall[0] -= 1
    if which == "mono_rollback": mono[0] -= 1
    if which == "wall_expiry": wall[0] += 599
    if which == "mono_expiry": mono[0] += 599
    if which == "stale": wall[0] += 30; mono[0] += 30
    if which == "deadline": mono[0] += 14
    calls = []
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        op.dispatch(SimpleNamespace(put_item=lambda **kw: calls.append(kw)), "put_item", {}, deadline=114, write="ddb")
    assert calls == []


def test_ambiguous_dispatch_is_counted_and_terminal(tmp_path):
    op = operation(tmp_path)
    op.intent()
    calls = []
    def write(**kw):
        calls.append(kw)
        raise TimeoutError("private-canary")
    with pytest.raises(TimeoutError):
        op.dispatch(SimpleNamespace(put_item=write), "put_item", {}, deadline=114, write="ddb")
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        op.dispatch(SimpleNamespace(put_item=write), "put_item", {}, deadline=114, write="ddb")
    assert len(calls) == op.ddb_writes == op.calls == 1


def test_reentrant_and_concurrent_dispatch_never_duplicate_write(tmp_path):
    op = operation(tmp_path)
    op.intent()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def write(**kw):
        calls.append(kw)
        entered.set()
        assert release.wait(3)
        return {}
    thread = threading.Thread(target=lambda: op.dispatch(SimpleNamespace(put_item=write), "put_item", {}, deadline=114, write="ddb"))
    thread.start()
    assert entered.wait(3)
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        op.dispatch(SimpleNamespace(put_item=write), "put_item", {}, deadline=114, write="ddb")
    release.set()
    thread.join(3)
    assert len(calls) == 1 and not thread.is_alive()


def test_aggregate_cap_counts_reads_and_mutations_before_dispatch(tmp_path):
    op = operation(tmp_path, max_sdk_calls=1)
    raw = SimpleNamespace(get_item=lambda **_: {})
    op.dispatch(raw, "get_item", {}, deadline=114)
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        op.dispatch(raw, "get_item", {}, deadline=114)
    assert op.calls == 1


def test_cli_and_reprs_never_receive_secrets(capsys):
    with pytest.raises(SystemExit):
        runner.main(["--help"])
    output = capsys.readouterr().out
    assert "--authority-root" in output
    assert all(arg not in output for arg in ("--password", "--token", "--refresh-token", "--access-key"))
    assert "private-canary" not in repr(runner._PrivateSubmission("private-canary", True))


@pytest.mark.parametrize("arn", ["arn:aws:sts::123456789012:assumed-role/other-role/operator",
    "arn:aws:iam::123456789012:user/enroller", "arn:aws:iam::123456789012:root",
    "arn:aws:sts::999999999999:assumed-role/honda-mapit-mcp-dev-mapit-enroller/operator"])
def test_explicit_sdk_verifier_rejects_wrong_role_and_keeps_direct_configuration(monkeypatch, arn):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    built = []
    original = boto3.session.Session.client
    def capture(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        built.append(result)
        return result
    monkeypatch.setattr(boto3.session.Session, "client", capture)
    pair = runner.create_enrollment_clients(access_key="synthetic-access", secret_key="synthetic-secret",
        session_token="synthetic-session", deadline=114, direct_only=True,
        expected_role_arn=ROLE, monotonic=lambda: 100)
    assert pair.ssm.meta.config.proxies == {} and pair.ssm.meta.config.retries["total_max_attempts"] == 1
    with Stubber(built[1]) as stub:
        stub.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": arn, "UserId": "synthetic:user",
            "ResponseMetadata": {"HTTPStatusCode": 200}}, {})
        assert pair.account_verifier(pair.ssm, ACCOUNT) is False
        assert pair.account_verifier(pair.ssm, ACCOUNT) is False
        stub.assert_no_pending_responses()


def _capture_accepted_scenario(tmp_path, monkeypatch):
    """Reuse the complete owning private parser/coordinator fixture as preparation.

    Only synthetic fixture creation dispatches its historical fake writes. The
    fresh operator below is checked against the retained bytes, and its only
    mutations are modeled binding CAS and SSM session creation.
    """
    from scripts import run_dev_owner_enrolled_login as login
    from tests.test_run_dev_owner_enrolled_delivery import test_full_private_loader_to_pre_publish_update_and_accepted_readback
    from cryptography.hazmat.primitives.asymmetric import rsa
    captured, private_keys = {}, []
    original_login = login.run_post_delivery_login
    original_key = rsa.generate_private_key
    def save_key(*args, **kwargs):
        value = original_key(*args, **kwargs)
        private_keys.append(value)
        return value
    def save_login(**kwargs):
        captured.update(kwargs)
        return original_login(**kwargs)
    monkeypatch.setattr(rsa, "generate_private_key", save_key)
    monkeypatch.setattr(login, "run_post_delivery_login", save_login)
    seed = tmp_path / "seed"
    seed.mkdir()
    test_full_private_loader_to_pre_publish_update_and_accepted_readback(seed, monkeypatch, False)
    return captured, private_keys


@pytest.mark.skipif(os.name != "nt", reason="owner operator uses native Windows provenance")
@pytest.mark.parametrize("failure", [None, "real_monotonic", "pre_cap", "ambiguous_ddb", "wrong_role", "consent", "expired_cloud", "post_readback"])
def test_actual_private_preflight_to_sdk_shaped_enrollment_and_closed_post(tmp_path, monkeypatch, failure):
    boto3 = pytest.importorskip("boto3")
    from botocore.validate import validate_parameters
    from mapit.aws_binding_keys import BindingKeyMaterial, encode_binding_keys
    from tests.test_aws_dev_multiuser_entrypoint import _bundle
    from cryptography.hazmat.primitives.asymmetric import rsa
    import socket
    captured, private_keys = _capture_accepted_scenario(tmp_path, monkeypatch)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network forbidden"))
    delivery_root, paths = captured["delivery_root"], captured["private_paths"]
    loaded = runner.load_accepted_owner_delivery(delivery_root=delivery_root, private_paths=paths, acl_checker=lambda _: True)
    history = {p: p.read_bytes() for p in Path(delivery_root).rglob("*") if p.is_file()}
    current_clock = captured["clock"]
    current_mono = [100.0]
    wall = int(current_clock())
    physical_mono = runner.time.monotonic
    physical_started = physical_mono()
    mono_provider = physical_mono if failure == "real_monotonic" else lambda: current_mono[0]
    wall_provider = (lambda: wall + physical_mono() - physical_started) if failure == "real_monotonic" else lambda: wall
    monkeypatch.setattr(runner.time, "time", wall_provider)
    root = tmp_path / "fresh-operation"
    root.mkdir()
    if failure == "real_monotonic":
        synthetic_archives = []
        for index in range(2):
            synthetic_archive = root / ("synthetic-public-archive-" + str(index))
            synthetic_archive.write_bytes(b"x" * 9_317_568)
            synthetic_archives.append(synthetic_archive)
        original_baseline_init = runner.AcceptedPrivateBaseline.__init__
        def native_with_archive(self, *args, **kwargs):
            original_baseline_init(self, *args, **kwargs)
            for synthetic_archive in synthetic_archives:
                _, _, fingerprint = runner._snapshot(synthetic_archive, maximum=10 * 1024 * 1024, acl_checker=lambda _: True)
                self.add(synthetic_archive, maximum=10 * 1024 * 1024, expected_fingerprint=fingerprint)
        monkeypatch.setattr(runner.AcceptedPrivateBaseline, "__init__", native_with_archive)
    fresh_authority = authority(loaded, authorized_from_epoch=wall - 1, authorized_until_epoch=wall + 599,
        state_directory=str(root.resolve()))
    if failure == "pre_cap": fresh_authority["max_sdk_calls"] = 1
    (root / "authorization.json").write_bytes(runner._canonical(fresh_authority))
    base = captured["bundle_factory"]()
    from tests.test_dev_owner_enrolled_runtime_readback import _OwnerEnrolledSdkScenario
    scenario = next(cell.cell_contents for cell in base.clients["sts"].get_caller_identity.__closure__
        if isinstance(cell.cell_contents, _OwnerEnrolledSdkScenario))
    dispatched_before = len(scenario.calls)
    monkeypatch.setattr(runner, "build_explicit_delivery_clients", lambda: base)
    # The independent invitation JWKS is fetched fresh; verify a real signed
    # MCP access token inside the actual consumer, never inject a forged grant.
    fresh_jwks = loaded.invitation_jwks
    invitation_jwk = json.loads(fresh_jwks)["keys"][0]
    invitation_kid = invitation_jwk["kid"]
    invitation_n = int.from_bytes(base64.urlsafe_b64decode(invitation_jwk["n"] + "=" * (-len(invitation_jwk["n"]) % 4)), "big")
    invitation_key = next(k for k in private_keys if k.public_key().public_numbers().n == invitation_n)
    class Channel:
        def __init__(self, policy, keys, consume, **kwargs):
            self.policy, self.consume = policy, consume
            assert kwargs["absolute_until_epoch"] <= fresh_authority["authorized_until_epoch"]
        def serve(self, *, ready_callback=None):
            policy = self.policy
            issued = int(wall_provider())
            token = jwt.encode({"iss": policy.issuer_url, "aud": policy.audience,
                "sub": policy.owner_subject, "client_id": policy.client_id, "token_use": "access",
                "iat": issued - 1, "exp": issued + 300, "scope": policy.required_scope}, invitation_key,
                algorithm="RS256", headers={"kid": invitation_kid})
            self.consume(token)
            return "verified"
    config = runner.MapitConfig(**loaded.private_inputs.manifest_inputs["public_config"])
    mapit_jwk = json.loads(loaded.mapit_jwks)["keys"][0]
    n = int.from_bytes(base64.urlsafe_b64decode(mapit_jwk["n"] + "=" * (-len(mapit_jwk["n"]) % 4)), "big")
    mapit_key = next(k for k in private_keys if k.public_key().public_numbers().n == n)
    mapit_token = jwt.encode({"iss": "https://cognito-idp.eu-west-1.amazonaws.com/" + config.user_pool_id,
        "aud": config.user_pool_client_id, "sub": "00000000-0000-4000-8000-0000000000bb",
        "token_use": "id", "iat": wall - 1, "exp": wall + 3600}, mapit_key,
        algorithm="RS256", headers={"kid": mapit_jwk["kid"]})
    material = BindingKeyMaterial(b"b" * 32, b"v" * 32)
    keys_value = encode_binding_keys(material, account_id=ACCOUNT, config=config, namespace="mapit", environment="dev")
    state = {"document": None, "session": None, "ddb_writes": 0, "ssm_writes": 0, "sts": 0}
    sdk_calls, pairs = [], []
    original_factory = boto3.session.Session.client
    role_session = "owner-mapit-" + fresh_authority["operation_id"]
    assumed = "arn:aws:sts::" + ACCOUNT + ":assumed-role/honda-mapit-mcp-dev-mapit-enroller/" + role_session
    def shape(raw, method, params, result):
        sdk_model = raw.meta.service_model.operation_model(raw.meta.method_to_api_mapping[method])
        validate_parameters(params, sdk_model.input_shape)
        validate_parameters({k: v for k, v in result.items() if k != "ResponseMetadata"}, sdk_model.output_shape)
        sdk_calls.append((raw.meta.service_model.service_name, method))
        return result
    def built_client(self, service, **kwargs):
        assert kwargs["config"].proxies == {}
        assert kwargs["aws_access_key_id"] == "ASIAEXAMPLE1234567890"
        raw = original_factory(self, service, **kwargs)
        pairs.append(raw)
        if service == "sts":
            def identity(**params):
                state["sts"] += 1
                arn = assumed if failure != "wrong_role" else assumed.replace("mapit-enroller", "wrong-enroller")
                return shape(raw, "get_caller_identity", params, {"Account": ACCOUNT, "Arn": arn,
                    "UserId": "AROAEXAMPLE:" + role_session, "ResponseMetadata": {"HTTPStatusCode": 200}})
            raw.get_caller_identity = identity
        elif service == "dynamodb":
            def get(**params):
                result = {"ResponseMetadata": {"HTTPStatusCode": 200}}
                if state["document"] is not None:
                    result["Item"] = copy.deepcopy(state["document"])
                return shape(raw, "get_item", params, result)
            def put(**params):
                assert params["TableName"].endswith(":table/honda-mapit-mcp-dev-mapit-identity-bindings")
                assert (root / "intent.json").is_file()
                state["ddb_writes"] += 1
                state["document"] = copy.deepcopy(params["Item"])
                result = shape(raw, "put_item", params, {"ResponseMetadata": {"HTTPStatusCode": 200}})
                if failure == "ambiguous_ddb":
                    raise TimeoutError("private-ambiguous-canary")
                return result
            raw.get_item, raw.put_item = get, put
        elif service == "ssm":
            def get(**params):
                path = params["Name"].removesuffix(":1")
                value = keys_value if path.endswith("mapit-identity-binding-config") else state["session"]
                return shape(raw, "get_parameter", params, {"Parameter": {"Name": path,
                    "ARN": "arn:aws:ssm:eu-west-1:" + ACCOUNT + ":parameter" + path,
                    "Type": "SecureString", "Version": 1, "Selector": ":1", "DataType": "text", "Value": value},
                    "ResponseMetadata": {"HTTPStatusCode": 200}})
            def put(**params):
                assert params["Overwrite"] is False and state["session"] is None
                state["ssm_writes"] += 1
                state["session"] = params["Value"]
                return shape(raw, "put_parameter", params, {"Version": 1, "Tier": "Standard",
                    "ResponseMetadata": {"HTTPStatusCode": 200}})
            raw.get_parameter, raw.put_parameter = get, put
        return raw
    monkeypatch.setattr(boto3.session.Session, "client", built_client)
    def assume(**params):
        assert params == {"RoleArn": ROLE, "RoleSessionName": role_session, "DurationSeconds": 900}
        return {"Credentials": {"AccessKeyId": "ASIAEXAMPLE1234567890", "SecretAccessKey": "S" * 40,
            "SessionToken": "synthetic-session", "Expiration": datetime.fromtimestamp(wall + 900, timezone.utc)},
            "AssumedRoleUser": {"Arn": assumed, "AssumedRoleId": "AROAEXAMPLE:" + role_session},
            "ResponseMetadata": {"HTTPStatusCode": 200}}
    base.clients["sts"].assume_role = assume
    original_ddb_get = base.clients["dynamodb"].get_item
    def base_ddb_get(**params):
        if params["Key"]["key"]["S"] == "identity-bindings-v1" and state["document"] is not None:
            return {"Item": copy.deepcopy(state["document"]), "ResponseMetadata": {"HTTPStatusCode": 200}}
        return original_ddb_get(**params)
    base.clients["dynamodb"].get_item = base_ddb_get
    original_ssm_get = base.clients["ssm"].get_parameter
    def base_ssm_get(**params):
        if params["Name"] == "/honda-mapit-mcp/dev/mapit-identity-binding-config":
            path = params["Name"]
            published = loaded.private_inputs.manifest_inputs["publication"]
            return {"Parameter": {"Name": path, "ARN": "arn:aws:ssm:eu-west-1:" + ACCOUNT + ":parameter" + path,
                "Type": "SecureString", "DataType": "text", "Version": 1, "Value": "opaque-encrypted-config",
                "LastModifiedDate": datetime.fromtimestamp(published["start"] + 1, timezone.utc)},
                "ResponseMetadata": {"HTTPStatusCode": 200}}
        if "/tenants/" in params["Name"] and state["session"] is not None:
            path = params["Name"]
            return {"Parameter": {"Name": path, "ARN": "arn:aws:ssm:eu-west-1:" + ACCOUNT + ":parameter" + path,
                "Type": "SecureString", "DataType": "text", "Version": 1, "Value": "opaque-encrypted-value",
                "LastModifiedDate": datetime.fromtimestamp(wall, timezone.utc)},
                "ResponseMetadata": {"HTTPStatusCode": 200}}
        return original_ssm_get(**params)
    base.clients["ssm"].get_parameter = base_ssm_get
    original_parameters = base.clients["ssm"].describe_parameters
    def parameters(**params):
        path = params["ParameterFilters"][0]["Values"][0]
        if "/tenants/" in path:
            return {"Parameters": [{"Name": path, "Type": "SecureString", "Version": 1,
                "Tier": "Standard", "DataType": "text", "KeyId": "alias/aws/ssm",
                "LastModifiedUser": assumed, "LastModifiedDate": datetime.fromtimestamp(wall, timezone.utc),
                "Policies": []}], "ResponseMetadata": {"HTTPStatusCode": 200}}
        return original_parameters(**params)
    base.clients["ssm"].describe_parameters = parameters
    def direct(request, *, timeout):
        payload = json.loads(request.data)
        target = request.headers["X-amz-target"]
        assert 0 < timeout <= 2
        if target.endswith("InitiateAuth"):
            assert payload["AuthParameters"]["REFRESH_TOKEN"] == "private-refresh-canary"
            response = {"AuthenticationResult": {"IdToken": mapit_token, "AccessToken": "synthetic-mapit-access", "ExpiresIn": 3600}}
            if failure == "expired_cloud": current_mono[0] += 14
        elif target.endswith("GetId"):
            response = {"IdentityId": "eu-west-1:bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"}
        else:
            response = {"Credentials": {"AccessKeyId": "synthetic", "SecretKey": "synthetic-secret",
                "SessionToken": "synthetic-session", "Expiration": wall + 3600}}
        stream = io.BytesIO(json.dumps(response).encode())
        stream.status = 200
        return stream
    monkeypatch.setattr(runner, "open_direct", direct)
    def private(**kwargs):
        if failure == "real_monotonic":
            assert 0 < kwargs["deadline"] - physical_mono() <= 300
        else:
            assert kwargs["deadline"] == 400  # grant expiry, not a new 600-second lease
        return runner._PrivateSubmission("private-refresh-canary", failure != "consent")
    if failure == "post_readback":
        original_concurrency = base.clients["lambda"].get_function_concurrency
        base.clients["lambda"].get_function_concurrency = lambda **p: (
            {"ReservedConcurrentExecutions": 1, "ResponseMetadata": {"HTTPStatusCode": 200}}
            if state["ssm_writes"] else original_concurrency(**p))
    result = runner.run_owner_mapit_enrollment(authority_root=root, delivery_root=delivery_root,
        private_paths=paths, source_sha=SOURCE, ci_run_id=999, acl_checker=lambda _: True,
        source_validator=lambda _: None, protection_reader=lambda **_: (12, 34),
        channel_factory=Channel, private_collector=private, jwks_fetcher=lambda _: fresh_jwks,
        clock=wall_provider, monotonic=mono_provider)
    success = failure in {None, "real_monotonic"}
    assert result["ok"] is success, (result, sdk_calls)
    if success:
        assert result["category"] == "owner_mapit_enrollment_verified"
        assert state["ddb_writes"] == result["ddb_writes"] == 3
        assert state["ssm_writes"] == result["ssm_writes"] == 1
        assert state["sts"] == 3  # separate key loader, DDB writer and SSM publisher leases
        assert (root / "result.json").is_file()
        assert len(pairs) == 5
        assert result["auth_calls"] == 3
        print(f"{failure or 'synthetic-clock'} composition: SDK={result['calls']}, auth={result['auth_calls']}, CAS=3, SSM=1")
    elif failure == "ambiguous_ddb":
        assert state["ddb_writes"] == 1 and state["ssm_writes"] == 0
    elif failure == "pre_cap":
        assert result["calls"] == 1
        assert len(scenario.calls) - dispatched_before == 1
        assert state["ddb_writes"] == state["ssm_writes"] == 0
    elif failure in {"wrong_role", "consent"}:
        assert state["ddb_writes"] == state["ssm_writes"] == 0
    elif failure == "expired_cloud":
        assert state["ddb_writes"] == 1 and state["ssm_writes"] == 0
    elif failure == "post_readback":
        assert state["ddb_writes"] == 3 and state["ssm_writes"] == 1
        assert not (root / "result.json").exists()
    assert all(p.read_bytes() == raw for p, raw in history.items())
    persisted = b"".join(p.read_bytes() for p in root.iterdir())
    assert b"private-refresh-canary" not in persisted and mapit_token.encode() not in persisted
    assert "private-refresh-canary" not in repr(result)


@pytest.mark.parametrize("change", ["first_revision_condition", "revision_jump", "extra_tenant", "active_first", "wrong_owner", "wrong_namespace"])
def test_owner_first_cas_cannot_modify_a_nonempty_or_crossed_document(tmp_path, change):
    op = operation(tmp_path)
    op.intent()
    raw_calls = []
    raw = SimpleNamespace(meta=object(), put_item=lambda **kw: raw_calls.append(kw))
    table = "arn:aws:dynamodb:eu-west-1:" + ACCOUNT + ":table/honda-mapit-mcp-dev-mapit-identity-bindings"
    wrapper = runner._BoundClient(raw, op, deadline=114, table=table,
        row_key="identity-bindings-v1", writable=True)
    row = {"tenant_key": KEY, "environment": "dev", "identity_tag": None,
        "secret_path": "/honda-mapit-mcp/dev/tenants/" + KEY + "/mapit-refresh-token",
        "secret_version": 1, "status": "pending", "revision": 1, "proof_envelope": None,
        "record_mac": "a" * 64}
    document = {"schema": 1, "records": [row]}
    request = {"TableName": table, "Item": {"key": {"S": "identity-bindings-v1"}, "revision": {"N": "1"},
        "payload": {"S": ""}, "mac": {"S": "b" * 64}}, "ReturnValues": "NONE",
        "ReturnConsumedCapacity": "NONE", "ConditionExpression": "attribute_not_exists(#pk)",
        "ExpressionAttributeNames": {"#pk": "key"}}
    if change == "first_revision_condition":
        request.update(ConditionExpression="#revision = :revision", ExpressionAttributeNames={"#revision": "revision"},
            ExpressionAttributeValues={":revision": {"N": "1"}})
    elif change == "revision_jump": request["Item"]["revision"] = {"N": "2"}
    elif change == "extra_tenant": document["records"].append(dict(row, tenant_key="tenant-" + "b" * 64))
    elif change == "active_first": row["status"] = "active"
    elif change == "wrong_owner": row["tenant_key"] = "tenant-" + "b" * 64
    else: row["secret_path"] = row["secret_path"].replace("/dev/", "/prod/")
    request["Item"]["payload"]["S"] = runner._canonical(document).decode()
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        wrapper.put_item(**request)
    assert raw_calls == [] and op.calls == 0 and op.ddb_writes == 0
