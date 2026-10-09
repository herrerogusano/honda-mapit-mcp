from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from mapit.aws_binding_keys import BindingKeyMaterial, MAPIT_PARAMETER_PATH, decode_binding_keys, encode_binding_keys
from mapit.config import MapitConfig
from scripts.build_aws_dev_mapit_binding_bootstrap import OPERATOR_ROLE_NAME
from scripts.dev_mapit_binding_key_setup import publish_mapit_keys


ACCOUNT = "123456789012"
CONFIG = MapitConfig(
    user_pool_id="eu-west-1_MapitPool123", user_pool_client_id="MapitClient123",
    identity_pool_id="eu-west-1:12345678-1234-1234-1234-123456789abc",
    discovery_enabled=False, http_timeout=2,
)
SOURCE = "a" * 40
BOOTSTRAP = "b" * 64
PARAMETER_ARN = f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{MAPIT_PARAMETER_PATH}"


class _Journal:
    def __init__(self):
        self.state = None
        self.saves = []

    def locked(self):
        return nullcontext()

    def load(self):
        return self.state

    def save(self, value):
        self.state = dict(value)
        self.saves.append(dict(value))


class _Missing(Exception):
    response = {"Error": {"Code": "ParameterNotFound"}, "ResponseMetadata": {"HTTPStatusCode": 400}}


def _meta(service):
    return SimpleNamespace(
        service_model=SimpleNamespace(service_name=service), region_name="eu-west-1",
        endpoint_url=f"https://{service}.eu-west-1.amazonaws.com",
        config=SimpleNamespace(retries={"total_max_attempts": 1}, proxies={}, signature_version="v4",
                               connect_timeout=2, read_timeout=3),
    )


class _Endpoint:
    def __init__(self):
        self.http_session = SimpleNamespace(_verify=True)


class _STS:
    def __init__(self, account=ACCOUNT, role=OPERATOR_ROLE_NAME):
        self.meta = _meta("sts")
        self._endpoint = _Endpoint()
        self.account, self.role = account, role
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200}, "Account": self.account,
            "Arn": f"arn:aws:sts::{self.account}:assumed-role/{self.role}/mapit-setup-01",
        }


class _SSM:
    def __init__(self):
        self.meta = _meta("ssm")
        self._endpoint = _Endpoint()
        self.value = None
        self.version = 1
        self.calls = []
        self.unknown_put = False
        self.invalid_ack = False

    def get_parameter(self, *, Name, WithDecryption):
        self.calls.append(("get", Name, WithDecryption))
        if self.value is None:
            raise _Missing()
        versioned = Name.endswith(":1")
        parameter = {
            "Name": MAPIT_PARAMETER_PATH,
            "ARN": PARAMETER_ARN,
            "Type": "SecureString",
            "DataType": "text",
            "Version": 1 if versioned else self.version,
            "LastModifiedDate": datetime(2026, 10, 9, tzinfo=timezone.utc),
        }
        if WithDecryption:
            parameter["Value"] = self.value
        if versioned:
            parameter["Selector"] = ":1"
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": parameter}

    def put_parameter(self, **request):
        self.calls.append(("put", {key: value for key, value in request.items() if key != "Value"}))
        assert request["Name"] == MAPIT_PARAMETER_PATH and request["Overwrite"] is False
        if self.value is not None:
            raise AssertionError("overwrite denied")
        self.value = request["Value"]
        if self.unknown_put:
            raise TimeoutError("private-canary")
        return {"ResponseMetadata": {"HTTPStatusCode": 200},
                "Version": 1, "Tier": "Advanced" if self.invalid_ack else "Standard"}


def _call(clients, journal, *, monotonic=lambda: 100.0, clock=lambda: 1_800_000_050, config=CONFIG):
    return publish_mapit_keys(
        clients, journal, account_id=ACCOUNT, config=config, source_sha=SOURCE,
        run_id=17, bootstrap_sha256=BOOTSTRAP, start=1_800_000_000,
        end=1_800_003_600, clock=clock, monotonic=monotonic,
    )


def _clients():
    ssm = _SSM()
    return {"sts": _STS(), "ssm": ssm}, ssm


def test_schema2_mapit_key_publication_is_create_only_and_bound_to_mapit_config():
    clients, ssm = _clients()
    journal = _Journal()
    result = _call(clients, journal)
    assert result == {"ok": True, "category": "key_publication_verified"}
    assert journal.state == {
        "schema": 1, "operation": "dev_mapit_binding_key_publication", "namespace": "mapit",
        "account": ACCOUNT, "source": SOURCE, "run_id": 17, "bootstrap_sha256": BOOTSTRAP,
        "parameter_path": MAPIT_PARAMETER_PATH, "start": 1_800_000_000,
        "end": 1_800_003_600, "phase": "accepted",
    }
    material = decode_binding_keys(ssm.value, account_id=ACCOUNT, config=CONFIG, namespace="mapit")
    assert len(material.binding_mac_key) == len(material.identity_proof_hmac_key) == 32
    assert [row[0] for row in ssm.calls] == ["get", "put", "get", "get"]
    put = next(row[1] for row in ssm.calls if row[0] == "put")
    assert put == {
        "Name": MAPIT_PARAMETER_PATH, "Type": "SecureString", "KeyId": "alias/aws/ssm",
        "Overwrite": False, "Tier": "Standard", "DataType": "text",
    }
    assert clients["sts"].calls == 4
    assert "Value" not in str(journal.state) and ssm.value not in str(journal.state)
    assert _call(clients, journal)["category"] == "key_publication_consumed"
    assert clients["sts"].calls == 4


def test_unknown_put_is_sticky_and_never_replayed():
    clients, ssm = _clients()
    ssm.unknown_put = True
    journal = _Journal()
    assert _call(clients, journal) == {"ok": False, "category": "key_publication_outcome_unknown"}
    assert journal.state["phase"] == "put_intent"
    before = len(ssm.calls)
    assert _call(clients, journal)["category"] == "key_publication_consumed"
    assert len(ssm.calls) == before
    assert sum(1 for row in ssm.calls if row[0] == "put") == 1


def test_malformed_put_ack_consumes_intent_without_readback_or_retry():
    clients, ssm = _clients()
    ssm.invalid_ack = True
    journal = _Journal()
    assert _call(clients, journal) == {"ok": False, "category": "key_publication_outcome_unknown"}
    assert journal.state["phase"] == "put_intent"
    assert [row for row in ssm.calls if row[0] == "put"]
    assert len([row for row in ssm.calls if row[0] == "get"]) == 1
    before = len(ssm.calls)
    assert _call(clients, journal)["category"] == "key_publication_consumed"
    assert len(ssm.calls) == before


@pytest.mark.parametrize("role", ["honda-mapit-mcp-dev-identity-enroller", "other-role"])
def test_only_exact_mapit_enroller_role_can_reach_parameter_preflight(role):
    clients, ssm = _clients()
    clients["sts"] = _STS(role=role)
    journal = _Journal()
    result = _call(clients, journal)
    assert result == {"ok": False, "category": "key_publication_unauthorized"}
    assert journal.state is None and ssm.calls == []


def test_legacy_synthetic_role_and_existing_mapit_path_are_not_reused():
    clients, ssm = _clients()
    clients["sts"] = _STS(role="honda-mapit-mcp-dev-identity-enroller")
    journal = _Journal()
    result = _call(clients, journal)
    assert result["ok"] is False
    assert journal.state is None and ssm.calls == []

    clients, ssm = _clients()
    ssm.value = "already-exists"
    journal = _Journal()
    assert _call(clients, journal)["category"] == "key_publication_exists"
    assert journal.state is None
    assert not any(row[0] == "put" for row in ssm.calls)


def test_invalid_config_and_short_window_fail_before_aws_or_intent():
    clients, ssm = _clients()
    journal = _Journal()
    invalid = MapitConfig(user_pool_id="eu-west-1_Invalid", user_pool_client_id="x")
    assert _call(clients, journal, config=invalid)["ok"] is False
    assert journal.state is None and ssm.calls == [] and clients["sts"].calls == 0

    journal = _Journal()
    ticks = iter([100.0, 114.0])
    assert _call(clients, journal, monotonic=lambda: next(ticks))["ok"] is False
    assert journal.state is None and ssm.calls == [] and clients["sts"].calls == 0


def test_wrong_ssm_region_tls_or_proxy_is_rejected_before_calls():
    clients, ssm = _clients()
    ssm.meta.endpoint_url = "https://other.example"
    journal = _Journal()
    assert _call(clients, journal)["ok"] is False
    assert journal.state is None and ssm.calls == [] and clients["sts"].calls == 0

    clients, ssm = _clients()
    ssm._endpoint.http_session._verify = False
    assert _call(clients, _Journal())["ok"] is False
    assert ssm.calls == [] and clients["sts"].calls == 0

    clients, ssm = _clients()
    ssm.meta.config.proxies = {"https": "http://proxy.invalid"}
    assert _call(clients, _Journal())["ok"] is False
    assert ssm.calls == [] and clients["sts"].calls == 0


def test_latest_version_must_remain_one_after_create():
    clients, ssm = _clients()
    original = ssm.get_parameter

    def get_parameter(**kwargs):
        reply = original(**kwargs)
        if kwargs["Name"] == MAPIT_PARAMETER_PATH and ssm.value is not None:
            reply["Parameter"]["Version"] = 2
        return reply

    ssm.get_parameter = get_parameter
    journal = _Journal()
    assert _call(clients, journal) == {"ok": False, "category": "key_publication_unverified"}
    assert journal.state["phase"] == "put_intent"
    assert sum(1 for row in ssm.calls if row[0] == "put") == 1


def test_consumed_journal_does_not_generate_a_candidate(monkeypatch):
    from scripts import dev_mapit_binding_key_setup as key_setup

    clients, ssm = _clients()
    journal = _Journal()
    journal.state = {"phase": "put_intent"}
    monkeypatch.setattr(key_setup, "generate_binding_keys", lambda: (_ for _ in ()).throw(AssertionError()))
    assert _call(clients, journal)["category"] == "key_publication_consumed"
    assert clients["sts"].calls == 0 and ssm.calls == []


def test_botocore_stubber_accepts_exact_namespace_wire_contract(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config
    from botocore.stub import ANY, Stubber
    from scripts import dev_mapit_binding_key_setup as key_setup

    session = boto3.session.Session(
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="secret-placeholder-for-offline-stubber",
        aws_session_token="session-placeholder-for-offline-stubber",
        region_name="eu-west-1",
    )
    config = Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1},
                    proxies={}, signature_version="v4")
    sts = session.client("sts", endpoint_url="https://sts.eu-west-1.amazonaws.com", config=config, verify=True)
    ssm = session.client("ssm", endpoint_url="https://ssm.eu-west-1.amazonaws.com", config=config, verify=True)
    sts_stub, ssm_stub = Stubber(sts), Stubber(ssm)
    material = BindingKeyMaterial(b"b" * 32, b"i" * 32)
    encoded = encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG, namespace="mapit")
    monkeypatch.setattr(key_setup, "generate_binding_keys", lambda: material)
    sts_response = {"UserId": "AROAXAMPLE:mapit-setup-01", "Account": ACCOUNT,
        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{OPERATOR_ROLE_NAME}/mapit-setup-01",
        "ResponseMetadata": {"HTTPStatusCode": 200}}
    sts_stub.add_response("get_caller_identity", sts_response, {})
    ssm_stub.add_client_error("get_parameter", "ParameterNotFound", http_status_code=400,
        expected_params={"Name": MAPIT_PARAMETER_PATH, "WithDecryption": False})
    sts_stub.add_response("get_caller_identity", sts_response, {})
    sts_stub.add_response("get_caller_identity", sts_response, {})
    ssm_stub.add_response("put_parameter", {"Version": 1, "Tier": "Standard",
        "ResponseMetadata": {"HTTPStatusCode": 200}}, {
            "Name": MAPIT_PARAMETER_PATH, "Value": ANY, "Type": "SecureString",
            "KeyId": "alias/aws/ssm", "Overwrite": False, "Tier": "Standard", "DataType": "text",
        })
    ssm_stub.add_response("get_parameter", {"Parameter": {
        "Name": MAPIT_PARAMETER_PATH, "Type": "SecureString",
        "Version": 1, "LastModifiedDate": datetime(2026, 10, 9, tzinfo=timezone.utc),
        "ARN": PARAMETER_ARN, "DataType": "text",
    }, "ResponseMetadata": {"HTTPStatusCode": 200}},
        {"Name": MAPIT_PARAMETER_PATH, "WithDecryption": False})
    sts_stub.add_response("get_caller_identity", sts_response, {})
    ssm_stub.add_response("get_parameter", {"Parameter": {
        "Name": MAPIT_PARAMETER_PATH, "Type": "SecureString", "Value": encoded,
        "Version": 1, "Selector": ":1", "LastModifiedDate": datetime(2026, 10, 9, tzinfo=timezone.utc),
        "ARN": PARAMETER_ARN, "DataType": "text",
    }, "ResponseMetadata": {"HTTPStatusCode": 200}},
        {"Name": MAPIT_PARAMETER_PATH + ":1", "WithDecryption": True})
    sts_stub.activate(); ssm_stub.activate()
    journal = _Journal()
    result = _call({"sts": sts, "ssm": ssm}, journal)
    assert result == {"ok": True, "category": "key_publication_verified"}
    assert journal.state["phase"] == "accepted"
    sts_stub.assert_no_pending_responses(); ssm_stub.assert_no_pending_responses()
    sts_stub.deactivate(); ssm_stub.deactivate()
