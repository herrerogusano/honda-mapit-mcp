from __future__ import annotations

import json
from pathlib import Path

import pytest
pytest.importorskip("botocore")  # mandatory in the pinned SDK CI job

from botocore.exceptions import ClientError

from scripts import deploy_multiuser as deploy

MAPIT = {"region": "eu-west-1", "user_pool_id": "eu-west-1_Mapit1234", "user_pool_client_id": "MapitClient1",
         "identity_pool_id": "eu-west-1:11111111-2222-4333-8444-555555555555",
         "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
         "discovery_enabled": False, "http_timeout": 2}
SECRET_MARKER = "MapitClient1"


def _config(tmp_path: Path, env="dev", **overrides) -> Path:
    value = {"domain_prefix": "hm-mapit-dev", "codex_callback_url": "http://127.0.0.1:1455/auth/callback",
             "codex_callback_port": 1455, "mapit_config": MAPIT, "privacy_contact": "owner@example.com"}
    if env == "prod":
        value["budget_email"] = "owner@example.com"
    value.update(overrides)
    path = tmp_path / f"private-{env}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _missing():
    return ClientError({"Error": {"Code": "ValidationError", "Message": "Stack with id x does not exist"}},
                       "DescribeStacks")


class FakeCfn:
    def __init__(self, existing=None, no_changes=()):
        self.stacks = dict(existing or {})
        self.no_changes = set(no_changes)
        self.change_sets: dict[tuple[str, str], dict] = {}
        self.executed: list[tuple[str, str]] = []
        self.deleted: list = []

    def describe_stacks(self, StackName):
        if StackName not in self.stacks:
            raise _missing()
        status, outputs = self.stacks[StackName]
        return {"Stacks": [{"StackStatus": status,
                            "Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in outputs.items()]}]}

    def create_change_set(self, **kwargs):
        name = kwargs["StackName"]
        assert set(kwargs["Capabilities"]) == {"CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"}
        json.loads(kwargs["TemplateBody"])
        if kwargs["ChangeSetType"] == "CREATE" and name not in self.stacks:
            self.stacks[name] = ("REVIEW_IN_PROGRESS", {})
        self.change_sets[(name, kwargs["ChangeSetName"])] = kwargs

    def describe_change_set(self, StackName, ChangeSetName, NextToken=None):
        if StackName in self.no_changes:
            return {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes."}
        if NextToken is None:
            return {"Status": "CREATE_COMPLETE", "NextToken": "p2", "Changes": [
                {"ResourceChange": {"Action": "Add", "LogicalResourceId": "UserPool",
                                    "ResourceType": "AWS::Cognito::UserPool"}}]}
        return {"Status": "CREATE_COMPLETE", "Changes": [
            {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "McpFunction",
                                "ResourceType": "AWS::Lambda::Function", "Replacement": "False"}}]}

    def execute_change_set(self, StackName, ChangeSetName):
        self.executed.append((StackName, ChangeSetName))
        outputs = {"BucketName": "artifact-bucket"} if StackName.endswith("artifacts") else {
            "McpUrl": "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp"}
        created = self.stacks[StackName][0] == "REVIEW_IN_PROGRESS"
        self.stacks[StackName] = ("CREATE_COMPLETE" if created else "UPDATE_COMPLETE", outputs)

    def delete_change_set(self, **kwargs):  # must never be called
        self.deleted.append(kwargs)


class FakeS3:
    def __init__(self, present=False):
        self.present = present
        self.puts = []

    def head_object(self, Bucket, Key):
        if not self.present:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {}

    def put_object(self, **kwargs):
        self.puts.append((kwargs["Bucket"], kwargs["Key"]))


class FakeSts:
    def __init__(self, arn="arn:aws:iam::123456789012:user/operator"):
        self.arn = arn

    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": self.arn}


def _build(tmp_path):
    def build(_workdir):
        path = tmp_path / "zip.zip"
        path.write_bytes(b"zip")
        return path, "c" * 64
    return build


def _run(tmp_path, cfn, s3=None, *, env="dev", execute=False, sts=None):
    lines = []
    config = deploy.load_private_config(_config(tmp_path, env), env)
    clients = deploy.Clients(sts or FakeSts(), cfn, s3 or FakeS3())
    code = deploy.run(env, config, clients, execute=execute, build=_build(tmp_path), out=lines.append,
                      sleep=lambda _s: None, change_set_suffix=lambda: "20261023000000")
    return code, lines


EXISTING_ARTIFACTS = {"honda-mapit-mcp-dev-multiuser-artifacts": ("CREATE_COMPLETE", {"BucketName": "artifact-bucket"})}


def test_dry_run_creates_change_set_but_executes_nothing(tmp_path):
    cfn = FakeCfn(EXISTING_ARTIFACTS, no_changes={"honda-mapit-mcp-dev-multiuser-artifacts"})
    s3 = FakeS3()
    code, lines = _run(tmp_path, cfn, s3)
    assert code == 0
    assert cfn.executed == [] and cfn.deleted == []
    assert s3.puts == [("artifact-bucket", "runtime/" + "c" * 64 + ".zip")]
    request = cfn.change_sets[("honda-mapit-mcp-dev-multiuser", "deploy-20261023000000")]
    assert request["ChangeSetType"] == "CREATE"
    params = {p["ParameterKey"]: p["ParameterValue"] for p in request["Parameters"]}
    assert params["ArtifactKey"] == "runtime/" + "c" * 64 + ".zip"
    assert json.loads(params["MapitConfigJson"]) == MAPIT
    assert params["CodexCallbackPort"] == "1455" and params["Geography"] == "0"
    assert "BudgetEmail" not in params
    text = "\n".join(lines)
    assert SECRET_MARKER not in text and "owner@example.com" not in text
    assert "123456789012" not in text and "********9012" in text
    assert "McpFunction" in text and "UserPool" in text  # both change pages printed
    assert "execute-change-set" in text


def test_dry_run_without_artifacts_stack_stops_before_upload(tmp_path):
    cfn, s3 = FakeCfn(), FakeS3()
    code, lines = _run(tmp_path, cfn, s3)
    assert code == 0 and cfn.executed == [] and s3.puts == []
    assert ("honda-mapit-mcp-dev-multiuser", "deploy-20261023000000") not in cfn.change_sets
    assert any("--execute" in line for line in lines)


def test_execute_creates_both_stacks_and_skips_present_artifact(tmp_path):
    cfn, s3 = FakeCfn(), FakeS3(present=True)
    code, lines = _run(tmp_path, cfn, s3, execute=True)
    assert code == 0
    assert [name for name, _ in cfn.executed] == ["honda-mapit-mcp-dev-multiuser-artifacts",
                                                  "honda-mapit-mcp-dev-multiuser"]
    assert s3.puts == []
    assert any("McpUrl" in line for line in lines)


def test_update_and_no_change_paths(tmp_path):
    existing = dict(EXISTING_ARTIFACTS)
    existing["honda-mapit-mcp-dev-multiuser"] = ("UPDATE_COMPLETE", {})
    cfn = FakeCfn(existing, no_changes={"honda-mapit-mcp-dev-multiuser-artifacts", "honda-mapit-mcp-dev-multiuser"})
    code, lines = _run(tmp_path, cfn, execute=True)
    assert code == 0 and cfn.executed == []
    assert sum("no changes" in line for line in lines) == 2


def test_prod_passes_budget_email_and_rejects_root(tmp_path):
    existing = {"honda-mapit-mcp-prod-multiuser-artifacts": ("CREATE_COMPLETE", {"BucketName": "b"})}
    cfn = FakeCfn(existing, no_changes={"honda-mapit-mcp-prod-multiuser-artifacts"})
    code, lines = _run(tmp_path, cfn, env="prod")
    params = {p["ParameterKey"] for p in cfn.change_sets[("honda-mapit-mcp-prod-multiuser",
                                                          "deploy-20261023000000")]["Parameters"]}
    assert "BudgetEmail" in params and "owner@example.com" not in "\n".join(lines)
    with pytest.raises(deploy.DeployError, match="root"):
        _run(tmp_path, FakeCfn(), env="prod", sts=FakeSts("arn:aws:iam::123456789012:root"))


def test_busy_stack_is_refused(tmp_path):
    cfn = FakeCfn({"honda-mapit-mcp-dev-multiuser-artifacts": ("UPDATE_IN_PROGRESS", {})})
    with pytest.raises(deploy.DeployError, match="busy"):
        _run(tmp_path, cfn)


@pytest.mark.parametrize("overrides", [
    {"codex_callback_url": "https://127.0.0.1:1455/cb"},
    {"codex_callback_url": "http://evil.example:1455/cb"},
    {"codex_callback_port": 1456},
    {"domain_prefix": "Has_Upper"},
    {"domain_prefix": "my-cognito"},
    {"mapit_config": {**MAPIT, "password": "x"}},
    {"mapit_config": {**MAPIT, "region": "us-east-1"}},
    {"mapit_config": {**MAPIT, "discovery_enabled": True}},
    {"mapit_config": {**MAPIT, "http_timeout": 3}},
    {"mapit_config": {**MAPIT, "frontend_url": "https://app.mapit.me"}},
    {"mapit_config": {k: v for k, v in MAPIT.items() if k != "http_timeout"}},
    {"mapit_config": {**MAPIT, "core_api_url": "https://evil.example"}},
    {"mapit_config": {**MAPIT, "user_pool_id": "bad"}},
    {"privacy_contact": ""},
    {"geography": "yes"},
    {"unexpected": 1},
])
def test_private_config_validation(tmp_path, overrides):
    with pytest.raises(deploy.DeployError):
        deploy.load_private_config(_config(tmp_path, **overrides), "dev")


def test_prod_requires_budget_email_and_repr_is_redacted(tmp_path):
    path = _config(tmp_path, "dev")
    with pytest.raises(deploy.DeployError):
        deploy.load_private_config(path, "prod")
    config = deploy.load_private_config(path, "dev")
    assert SECRET_MARKER not in repr(config) and "owner@" not in repr(config)


def test_main_requires_wheel_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("HONDA_MAPIT_WHEEL_DIR", raising=False)
    clients = deploy.Clients(FakeSts(), FakeCfn(), FakeS3())
    assert deploy.main(["--env", "dev", "--private-config", str(_config(tmp_path))], clients=clients) == 1
    assert "wheel" in capsys.readouterr().err
