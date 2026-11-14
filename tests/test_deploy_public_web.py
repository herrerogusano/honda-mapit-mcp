"""Offline tests of the public web deploy CLI (doubles and botocore Stubber; no AWS)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
pytest.importorskip("botocore")  # mandatory in the pinned SDK CI job

import botocore.session
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from mapit import public_web
from scripts import build_public_web_stack as web_stack
from scripts import deploy_public_web as deploy
from tests.test_deploy_multiuser import MAPIT, FakeCfn, FakeS3, FakeSts, _build

ARTIFACTS = {"honda-mapit-mcp-dev-multiuser-artifacts": ("CREATE_COMPLETE", {"BucketName": "artifact-bucket"}),
             "honda-mapit-mcp-prod-multiuser-artifacts": ("CREATE_COMPLETE", {"BucketName": "artifact-bucket"})}
KEY_BYTES = bytes(range(32))
EMAIL = "alerts@example.org"


def _config(tmp_path: Path, env="dev", **overrides) -> Path:
    value = {"domain_prefix": "web-login-dev", "mapit_config": MAPIT, "alarm_email": EMAIL}
    if env == "prod":
        value["web_callback_url"] = "https://web.example.org/"
    value.update(overrides)
    path = tmp_path / f"web-{env}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class FakeSsm:
    def __init__(self, present=(), log=None):
        self.present = set(present)
        self.puts: list[dict] = []
        self.log = log if log is not None else []

    def describe_parameters(self, ParameterFilters):
        (item,) = ParameterFilters
        assert (item["Key"], item["Option"]) == ("Name", "Equals")
        return {"Parameters": [{"Name": name, "Type": "SecureString"} for name in item["Values"]
                               if name in self.present]}

    def put_parameter(self, **kwargs):
        self.log.append(("put_parameter", kwargs["Name"]))
        if kwargs["Name"] in self.present:
            raise ClientError({"Error": {"Code": "ParameterAlreadyExists", "Message": "x"}}, "PutParameter")
        self.puts.append(kwargs)
        self.present.add(kwargs["Name"])
        return {"Version": 1, "Tier": "Standard"}

    def get_parameter(self, **kwargs):  # must never be called: the deploy never reads a value
        raise AssertionError("value read")


class OrderedCfn(FakeCfn):
    def __init__(self, existing, log):
        super().__init__(existing)
        self.log = log

    def execute_change_set(self, StackName, ChangeSetName):
        self.log.append(("execute", StackName))
        super().execute_change_set(StackName, ChangeSetName)


def _run(tmp_path, *, env="dev", execute=False, ssm=None, cfn=None, existing=ARTIFACTS):
    lines: list[str] = []
    log: list = []
    ssm = ssm or FakeSsm(log=log)
    cfn = cfn or OrderedCfn(existing, ssm.log)
    config = deploy.load_web_config(_config(tmp_path, env), env)
    clients = deploy.WebClients(FakeSts(), cfn, FakeS3(), ssm)
    code = deploy.run(env, config, clients, execute=execute, build=_build(tmp_path), out=lines.append,
                      sleep=lambda _s: None, change_set_suffix=lambda: "20261114000000",
                      token_bytes=lambda n: KEY_BYTES[:n])
    return code, lines, cfn, ssm


def test_dry_run_creates_only_the_change_set(tmp_path):
    code, lines, cfn, ssm = _run(tmp_path)
    assert code == 0 and cfn.executed == [] and ssm.puts == []
    ((stack, _),) = [key for key in cfn.change_sets if key[0] == "honda-mapit-mcp-dev-web"]
    assert stack == "honda-mapit-mcp-dev-web"
    assert all(key[0] == "honda-mapit-mcp-dev-web" for key in cfn.change_sets)  # artifacts stack untouched
    body = cfn.change_sets[("honda-mapit-mcp-dev-web", "deploy-20261114000000")]
    assert json.loads(body["TemplateBody"]) == web_stack.build_public_web_template("dev")
    assert "With --execute the fingerprint key is created first (Overwrite=False)." in lines
    assert any("Turnstile secret" in line and "absent" in line for line in lines)


def test_execute_creates_the_key_before_the_stack(tmp_path):
    code, lines, cfn, ssm = _run(tmp_path, execute=True)
    assert code == 0
    assert ssm.log == [("put_parameter", "/honda-mapit-mcp/dev/web/fingerprint-key"),
                       ("execute", "honda-mapit-mcp-dev-web")]
    (put,) = ssm.puts
    assert (put["Type"], put["Overwrite"], put["Tier"]) == ("SecureString", False, "Standard")
    # Same encoding the functions read (FingerprintKeyStore), and never printed.
    assert public_web._decode_key(put["Value"]) == KEY_BYTES
    assert all(put["Value"] not in line for line in lines)


def test_existing_key_is_never_overwritten_or_read(tmp_path):
    name = public_web.fingerprint_key_parameter_name("dev")
    ssm = FakeSsm(present={name})
    code, lines, _cfn, ssm = _run(tmp_path, execute=True, ssm=ssm)
    assert code == 0 and ssm.puts == []
    assert f"Fingerprint key already present: {name}" in lines


def test_missing_artifacts_stack_stops_before_any_write(tmp_path):
    with pytest.raises(deploy.DeployError, match="artifacts stack"):
        _run(tmp_path, execute=True, existing={})


def test_prod_parameters_and_private_values_never_printed(tmp_path):
    code, lines, cfn, _ssm = _run(tmp_path, env="prod")
    assert code == 0
    params = {p["ParameterKey"]: p["ParameterValue"]
              for p in cfn.change_sets[("honda-mapit-mcp-prod-web", "deploy-20261114000000")]["Parameters"]}
    assert params["WebCallbackUrl"] == "https://web.example.org/"
    assert params["AlarmEmail"] == EMAIL and json.loads(params["MapitConfigJson"]) == MAPIT
    assert set(params) == set(web_stack.build_public_web_template("prod")["Parameters"])
    text = "\n".join(lines)
    assert EMAIL not in text and "MapitClient1" not in text


def test_reservations_are_empty_unless_configured(tmp_path):
    config = deploy.load_web_config(_config(tmp_path), "dev")
    params = {p["ParameterKey"]: p["ParameterValue"] for p in deploy.stack_parameters("dev", config, "k")}
    assert [params[f"{name}ReservedConcurrency"] for name in ("Identity", "Mcp", "Pass", "Sweep")] == [""] * 4
    config = deploy.load_web_config(_config(tmp_path, reserved_concurrency={"identity": 5, "sweep": 1}), "dev")
    params = {p["ParameterKey"]: p["ParameterValue"] for p in deploy.stack_parameters("dev", config, "k")}
    assert (params["IdentityReservedConcurrency"], params["McpReservedConcurrency"],
            params["SweepReservedConcurrency"]) == ("5", "", "1")


@pytest.mark.parametrize(("env", "overrides"), [
    ("dev", {"web_callback_url": "https://web.example.org/"}),  # dev return URL is fixed
    ("dev", {"alarm_email": "not-an-email"}),
    ("dev", {"domain_prefix": "my-cognito-login"}),
    ("dev", {"reserved_concurrency": {"identity": 0}}),
    ("dev", {"reserved_concurrency": {"other": 1}}),
    ("dev", {"reserved_concurrency": {"mcp": True}}),
    ("dev", {"extra": 1}),
    ("prod", {"web_callback_url": "http://web.example.org/"}),
    ("prod", {"web_callback_url": "https://web.example.org:8443/"}),
])
def test_private_config_validation(tmp_path, env, overrides):
    with pytest.raises(deploy.DeployError):
        deploy.load_web_config(_config(tmp_path, env, **overrides), env)


def test_prod_requires_a_callback_and_repr_is_redacted(tmp_path):
    path = _config(tmp_path, "prod")
    value = json.loads(path.read_text(encoding="utf-8"))
    del value["web_callback_url"]
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(deploy.DeployError):
        deploy.load_web_config(path, "prod")
    assert EMAIL not in repr(deploy.load_web_config(_config(tmp_path, "prod"), "prod"))


def test_store_turnstile_secret_never_echoes_or_overwrites(capsys):
    ssm = FakeSsm()
    clients = deploy.WebClients(None, None, None, ssm)
    assert deploy.main(["--env", "dev", "--store-turnstile-secret"], clients=clients,
                       ask=lambda _prompt: "0x4AAAAAAAsecret") == 0
    (put,) = ssm.puts
    assert (put["Name"], put["Type"], put["Overwrite"]) == ("/honda-mapit-mcp/dev/web/turnstile-secret",
                                                            "SecureString", False)
    assert "0x4AAAAAAAsecret" not in capsys.readouterr().out
    assert deploy.main(["--env", "dev", "--store-turnstile-secret"], clients=clients, ask=lambda _p: "x") == 1
    assert "never overwrites" in capsys.readouterr().err


@pytest.mark.parametrize(("env", "secret"), [("dev", "with space"), ("dev", ""), ("prod", "1x0000000000000000000000000000000AA")])
def test_store_turnstile_secret_refuses_invalid_values(env, secret):
    ssm = FakeSsm()
    with pytest.raises(deploy.DeployError):
        deploy.store_turnstile_secret(ssm, env, ask=lambda _p: secret, out=lambda _l: None)
    assert ssm.puts == []


def test_store_mode_takes_only_env(tmp_path):
    clients = deploy.WebClients(None, None, None, FakeSsm())
    assert deploy.main(["--env", "dev", "--store-turnstile-secret", "--execute"], clients=clients) == 1


def _stubbed_ssm():
    client = botocore.session.get_session().create_client(
        "ssm", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")
    return client, Stubber(client)


def test_ssm_requests_match_the_sdk_model():
    client, stubber = _stubbed_ssm()
    name = public_web.fingerprint_key_parameter_name("dev")
    stubber.add_response("describe_parameters", {"Parameters": []}, {
        "ParameterFilters": [{"Key": "Name", "Option": "Equals", "Values": [name]}]})
    stubber.add_response("put_parameter", {"Version": 1, "Tier": "Standard"}, {
        "Name": name, "Value": deploy.new_fingerprint_key(lambda n: KEY_BYTES[:n]), "Type": "SecureString",
        "Overwrite": False, "Tier": "Standard"})
    stubber.add_client_error("put_parameter", service_error_code="ParameterAlreadyExists", http_status_code=400)
    with stubber:
        assert deploy.parameter_exists(client, name) is False
        assert deploy.ensure_fingerprint_key(client, "dev", lambda _l: None, lambda n: KEY_BYTES[:n]) is True
        assert deploy.ensure_fingerprint_key(client, "dev", lambda _l: None) is False
    stubber.assert_no_pending_responses()


def test_unconfirmed_or_failed_key_write_stops(tmp_path):
    client, stubber = _stubbed_ssm()
    stubber.add_response("put_parameter", {"Tier": "Standard"})
    stubber.add_client_error("put_parameter", service_error_code="AccessDeniedException", http_status_code=400)
    with stubber:
        with pytest.raises(deploy.DeployError, match="unconfirmed"):
            deploy.ensure_fingerprint_key(client, "dev", lambda _l: None)
        with pytest.raises(deploy.DeployError, match="AccessDeniedException"):
            deploy.ensure_fingerprint_key(client, "dev", lambda _l: None)


def test_a_non_secure_parameter_with_the_key_name_is_refused():
    class Plain(FakeSsm):
        def describe_parameters(self, ParameterFilters):
            return {"Parameters": [{"Name": ParameterFilters[0]["Values"][0], "Type": "String"}]}

    with pytest.raises(deploy.DeployError, match="not a SecureString"):
        deploy.parameter_exists(Plain(), public_web.fingerprint_key_parameter_name("dev"))
