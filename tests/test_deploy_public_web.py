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
CHANGE_SET = "deploy-20261114000000"
STACK = "honda-mapit-mcp-dev-web"


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


def _change(logical, action="Add", replacement=None):
    item = {"Action": action, "LogicalResourceId": logical, "ResourceType": "AWS::X::Y"}
    if replacement is not None:
        item["Replacement"] = replacement
    return {"ResourceChange": item}


class ReviewedCfn(FakeCfn):
    """A stack with one reviewed change set, described in two pages."""

    def __init__(self, existing, log, changes=None, status=("CREATE_COMPLETE", "AVAILABLE")):
        super().__init__(existing)
        self.log = log
        self.pages = changes if changes is not None else [[_change("UserPool")], [_change("McpFunction")]]
        self.status = status
        self.created = 0

    def create_change_set(self, **kwargs):
        self.created += 1
        super().create_change_set(**kwargs)

    def describe_change_set(self, StackName, ChangeSetName, NextToken=None):
        if self.created:  # review run: the base double
            return super().describe_change_set(StackName, ChangeSetName, NextToken)
        self.log.append(("describe", ChangeSetName, NextToken))
        index = 0 if NextToken is None else int(NextToken)
        page = {"Status": self.status[0], "ExecutionStatus": self.status[1], "Changes": self.pages[index]}
        if index + 1 < len(self.pages):
            page["NextToken"] = str(index + 1)
        return page

    def execute_change_set(self, StackName, ChangeSetName):
        self.log.append(("execute", StackName, ChangeSetName))
        self.stacks[StackName] = ("CREATE_COMPLETE", {
            "AlarmTopicArn": "arn:aws:sns:eu-west-1:123456789012:honda-mapit-mcp-dev-web-alarms"})


def _review(tmp_path, *, env="dev", ssm=None, existing=ARTIFACTS, out=None):
    lines: list[str] = []
    ssm = ssm or FakeSsm()
    cfn = ReviewedCfn(existing, ssm.log)
    s3 = FakeS3()
    config = deploy.load_web_config(_config(tmp_path, env), env)
    code = deploy.run(env, config, deploy.WebClients(FakeSts(), cfn, s3, ssm), build=_build(tmp_path),
                      out=out or lines.append, sleep=lambda _s: None, change_set_suffix=lambda: "20261114000000")
    return code, lines, cfn, ssm, s3


def _execute(*, ssm=None, changes=None, status=("CREATE_COMPLETE", "AVAILABLE"), allow=False,
             stack_status="REVIEW_IN_PROGRESS", name=CHANGE_SET, out=None, sts=None):
    lines: list[str] = []
    ssm = ssm or FakeSsm()
    cfn = ReviewedCfn({STACK: (stack_status, {})}, ssm.log, changes, status)
    code = deploy.execute("dev", deploy.WebClients(sts or FakeSts(), cfn, FakeS3(), ssm), name,
                          allow_replacement=allow, out=out or lines.append, sleep=lambda _s: None,
                          token_bytes=lambda n: KEY_BYTES[:n])
    return code, lines, cfn, ssm


# --- review run ------------------------------------------------------------------

def test_review_uploads_the_zip_and_creates_the_change_set_but_writes_no_ssm(tmp_path):
    code, lines, cfn, ssm, s3 = _review(tmp_path)
    assert code == 0 and cfn.executed == [] and ssm.puts == []
    assert s3.puts == [("artifact-bucket", "runtime/" + "c" * 64 + ".zip")]
    assert list(cfn.change_sets) == [(STACK, CHANGE_SET)]  # the artifacts stack is untouched
    assert cfn.stacks[STACK][0] == "REVIEW_IN_PROGRESS"
    body = cfn.change_sets[(STACK, CHANGE_SET)]
    assert json.loads(body["TemplateBody"]) == web_stack.build_public_web_template("dev")
    assert f"  python -m scripts.deploy_public_web --env dev --execute --change-set {CHANGE_SET}" in lines
    assert "Executing it first creates the fingerprint key (Overwrite=False)." in lines
    assert any("Turnstile secret" in line and "absent" in line for line in lines)


def test_missing_artifacts_stack_stops_the_review(tmp_path):
    with pytest.raises(deploy.DeployError, match="artifacts stack"):
        _review(tmp_path, existing={})


def test_prod_parameters_and_private_values_never_printed(tmp_path):
    code, lines, cfn, _ssm, _s3 = _review(tmp_path, env="prod")
    assert code == 0
    params = {p["ParameterKey"]: p["ParameterValue"]
              for p in cfn.change_sets[("honda-mapit-mcp-prod-web", CHANGE_SET)]["Parameters"]}
    assert params["WebCallbackUrl"] == "https://web.example.org/"
    assert params["AlarmEmail"] == EMAIL and json.loads(params["MapitConfigJson"]) == MAPIT
    assert set(params) == set(web_stack.build_public_web_template("prod")["Parameters"])
    text = "\n".join(lines)
    assert EMAIL not in text and "MapitClient1" not in text


# --- execute by name -------------------------------------------------------------

def test_execute_runs_the_reviewed_change_set_by_name_after_creating_the_key():
    code, lines, cfn, ssm = _execute()
    assert code == 0 and cfn.created == 0  # no new change set
    assert ssm.log == [("describe", CHANGE_SET, None), ("describe", CHANGE_SET, "1"),
                       ("put_parameter", "/honda-mapit-mcp/dev/web/fingerprint-key"),
                       ("execute", STACK, CHANGE_SET)]
    (put,) = ssm.puts
    assert (put["Type"], put["Overwrite"], put["Tier"]) == ("SecureString", False, "Standard")
    assert public_web._decode_key(put["Value"]) == KEY_BYTES  # the format FingerprintKeyStore reads


def test_the_key_value_never_reaches_stdout_or_stderr(capsys):
    code, _lines, _cfn, ssm = _execute(out=print)
    assert code == 0
    captured = capsys.readouterr()
    value = ssm.puts[0]["Value"]
    assert value not in captured.out and value not in captured.err
    assert "Fingerprint key created (value not shown)" in captured.out


def test_printed_outputs_mask_the_account_id():
    _code, lines, _cfn, _ssm = _execute()
    assert not any("123456789012" in line for line in lines)
    assert any("********9012" in line and "AlarmTopicArn" in line for line in lines)


# Pinned here, not read from the module: pool, login domain, web client and table.
@pytest.mark.parametrize("logical", ["UserPool", "UserPoolDomain", "WebClient", "WebStateTable"])
@pytest.mark.parametrize(("action", "replacement"), [("Remove", None), ("Modify", "True"), ("Modify", "Conditional")])
def test_removal_or_replacement_of_a_protected_resource_is_refused(logical, action, replacement):
    changes = [[_change("McpFunction", "Modify", "False")], [_change(logical, action, replacement)]]
    with pytest.raises(deploy.DeployError, match=f"refusing to remove or replace {logical}"):
        _execute(changes=changes, stack_status="UPDATE_COMPLETE")
    # Only with the explicit flag.
    code, _lines, cfn, _ssm = _execute(changes=changes, stack_status="UPDATE_COMPLETE", allow=True)
    assert code == 0 and cfn.log[-1] == ("execute", STACK, CHANGE_SET)


def test_refused_change_set_writes_nothing():
    ssm = FakeSsm()
    with pytest.raises(deploy.DeployError):
        _execute(ssm=ssm, changes=[[_change("WebStateTable", "Modify", "True")]], stack_status="UPDATE_COMPLETE")
    assert ssm.puts == [] and not any(item[0] == "execute" for item in ssm.log)


def test_modifications_without_replacement_and_other_resources_pass():
    changes = [[_change("UserPool", "Modify", "False"), _change("McpFunction", "Remove"),
                _change("PassFunction", "Modify", "True")]]
    assert deploy.protected_changes(changes[0]) == []
    code, _lines, _cfn, _ssm = _execute(changes=changes, stack_status="UPDATE_COMPLETE")
    assert code == 0


@pytest.mark.parametrize("status", [("FAILED", "UNAVAILABLE"), ("CREATE_COMPLETE", "EXECUTE_COMPLETE"),
                                    ("CREATE_COMPLETE", "OBSOLETE")])
def test_only_an_available_change_set_is_executed(status):
    with pytest.raises(deploy.DeployError, match="not ready"):
        _execute(status=status)


@pytest.mark.parametrize(("stack_status", "name"), [(None, CHANGE_SET), ("UPDATE_IN_PROGRESS", CHANGE_SET),
                                                    ("REVIEW_IN_PROGRESS", "other-name")])
def test_execute_needs_an_existing_idle_stack_and_a_review_name(stack_status, name):
    lines: list[str] = []
    ssm = FakeSsm()
    cfn = ReviewedCfn({STACK: (stack_status, {})} if stack_status else {}, ssm.log)
    with pytest.raises(deploy.DeployError):
        deploy.execute("dev", deploy.WebClients(FakeSts(), cfn, FakeS3(), ssm), name, out=lines.append)
    assert ssm.puts == []


def test_existing_key_is_never_overwritten_or_read():
    name = public_web.fingerprint_key_parameter_name("dev")
    code, lines, _cfn, ssm = _execute(ssm=FakeSsm(present={name}))
    assert code == 0 and ssm.puts == []
    assert f"Fingerprint key already present: {name}" in lines


def test_execute_refuses_root_credentials():
    ssm = FakeSsm()
    with pytest.raises(deploy.DeployError, match="root"):
        _execute(ssm=ssm, sts=FakeSts(arn="arn:aws:iam::123456789012:root"))
    assert ssm.log == []


@pytest.mark.parametrize("argv", [
    ["--execute"],
    ["--execute", "--change-set", CHANGE_SET, "--private-config", "x.json"],
    ["--change-set", CHANGE_SET, "--private-config", "x.json"],
    ["--allow-replacement", "--private-config", "x.json"],
])
def test_cli_keeps_review_and_execute_apart(argv):
    ssm = FakeSsm()
    assert deploy.main(["--env", "dev", *argv], clients=deploy.WebClients(FakeSts(), None, None, ssm)) == 1
    assert ssm.log == []


# --- configuration ---------------------------------------------------------------

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


# --- Turnstile secret ------------------------------------------------------------

def test_store_turnstile_secret_never_echoes_or_overwrites(capsys):
    ssm = FakeSsm()
    clients = deploy.WebClients(FakeSts(), None, None, ssm)
    assert deploy.main(["--env", "dev", "--store-turnstile-secret"], clients=clients,
                       ask=lambda _prompt: "0x4AAAAAAAsecret") == 0
    (put,) = ssm.puts
    assert (put["Name"], put["Type"], put["Overwrite"]) == ("/honda-mapit-mcp/dev/web/turnstile-secret",
                                                            "SecureString", False)
    captured = capsys.readouterr()
    assert "0x4AAAAAAAsecret" not in captured.out + captured.err
    assert deploy.main(["--env", "dev", "--store-turnstile-secret"], clients=clients, ask=lambda _p: "x") == 1
    assert "never overwrites" in capsys.readouterr().err


def test_store_turnstile_secret_checks_the_caller_before_asking():
    asked = []
    ssm = FakeSsm()
    clients = deploy.WebClients(FakeSts(arn="arn:aws:iam::123456789012:root"), None, None, ssm)
    with pytest.raises(deploy.DeployError, match="root"):
        deploy.store_turnstile_secret(clients, "dev", ask=lambda p: asked.append(p) or "secret", out=lambda _l: None)
    assert asked == [] and ssm.puts == []


@pytest.mark.parametrize(("env", "secret"), [("dev", "with space"), ("dev", ""), ("prod", "1x0000000000000000000000000000000AA")])
def test_store_turnstile_secret_refuses_invalid_values(env, secret):
    ssm = FakeSsm()
    clients = deploy.WebClients(FakeSts(), None, None, ssm)
    with pytest.raises(deploy.DeployError):
        deploy.store_turnstile_secret(clients, env, ask=lambda _p: secret, out=lambda _l: None)
    assert ssm.puts == []


def test_store_mode_takes_only_env():
    clients = deploy.WebClients(FakeSts(), None, None, FakeSsm())
    assert deploy.main(["--env", "dev", "--store-turnstile-secret", "--execute"], clients=clients) == 1


# --- SSM requests against the SDK model -------------------------------------------

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


def test_change_set_requests_match_the_sdk_model():
    client = botocore.session.get_session().create_client(
        "cloudformation", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")
    stubber = Stubber(client)
    stubber.add_response("describe_change_set", {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                                                 "NextToken": "t", "Changes": [{"Type": "Resource", "ResourceChange": {
                                                     "Action": "Modify", "LogicalResourceId": "UserPool",
                                                     "Replacement": "Conditional"}}]},
                         {"StackName": STACK, "ChangeSetName": CHANGE_SET})
    stubber.add_response("describe_change_set", {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                                                 "Changes": []},
                         {"StackName": STACK, "ChangeSetName": CHANGE_SET, "NextToken": "t"})
    with stubber:
        changes = deploy._reviewed_changes(client, STACK, CHANGE_SET)
    assert deploy.protected_changes(changes) == ["UserPool"]


def test_unconfirmed_or_failed_key_write_stops():
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
