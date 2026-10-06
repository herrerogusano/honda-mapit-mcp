import scripts.probe_github_dev_read_permissions as probe
from scripts.probe_github_dev_read_permissions import run


def context():
    return {"GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp", "GITHUB_REF": "refs/heads/develop",
            "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY_OWNER_ID": "1", "GH_TOKEN": "secret-fixture"}


def test_three_fixed_reads_no_payload_output(tmp_path):
    calls = []
    class Reader:
        def __init__(self, token, root):
            assert token == "secret-fixture" and root == tmp_path
        def remote(self, endpoint):
            calls.append(endpoint)
            return {"private": "cannot-escape"}
    result = run(context(), root=tmp_path, transport_factory=Reader)
    assert len(calls) == 3
    assert all(result[k] for k in ("context_verified", "branch_readable", "environment_readable", "branch_policy_readable"))
    assert result["protections_verified"] is False
    assert "cannot-escape" not in repr(result) and "secret-fixture" not in repr(result)


def test_denied_reads_remain_false_and_do_not_retry(tmp_path):
    calls = []
    class Reader:
        def __init__(self, *args): pass
        def remote(self, endpoint):
            calls.append(endpoint); raise ValueError("private-provider-data")
    result = run(context(), root=tmp_path, transport_factory=Reader)
    assert len(calls) == 3 and result["context_verified"] is True
    assert not any(result[k] for k in ("branch_readable", "environment_readable", "branch_policy_readable", "protections_verified"))


def test_wrong_ref_never_constructs_transport(tmp_path):
    env = context(); env["GITHUB_REF"] = "refs/heads/main"
    def reader(*args): raise AssertionError("called")
    assert run(env, root=tmp_path, transport_factory=reader)["context_verified"] is False


def test_read_permission_probe_must_not_exit_success_when_protection_reads_are_denied(monkeypatch, capsys):
    denied = {"read_only": True, "context_verified": True, "branch_readable": False,
              "environment_readable": False, "branch_policy_readable": False,
              "protections_verified": False}
    monkeypatch.setattr(probe, "run", lambda *args, **kwargs: denied)
    monkeypatch.setattr(probe.os, "environ", context())
    assert probe.main() == 1
