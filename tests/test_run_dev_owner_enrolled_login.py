from types import SimpleNamespace

import pytest

from scripts import run_dev_owner_enrolled_login as runner


@pytest.mark.parametrize("stage", ["source", "protections", "inputs", "input_integrity"])
def test_failed_initial_gate_never_constructs_sdk_or_listener(stage):
    events = []
    def source(_value):
        events.append("source")
        if stage == "source":
            raise ValueError("private provider detail")
    def protections(**_kwargs):
        events.append("protections")
        if stage == "protections":
            raise ValueError("private protection detail")
        return 12, 34
    def load(**_kwargs):
        events.append("inputs")
        if stage == "inputs":
            raise ValueError("private path")
        return SimpleNamespace(assert_unchanged=lambda: False)
    def forbidden():
        pytest.fail("SDK must not be constructed")
    result = runner.run_post_delivery_login(delivery_root="unused", private_paths={},
        source_sha="f" * 40, ci_run_id=42, source_validator=source,
        protection_reader=protections, accepted_loader=load, bundle_factory=forbidden)
    assert result == {"ok": False, "category": "owner_enrolled_login_unverified", "calls": 0}
    assert events[0] == "source"


@pytest.mark.parametrize("now", [float("nan"), float("inf"), True, -1])
def test_invalid_clock_stops_before_sdk(now):
    evidence = SimpleNamespace(assert_unchanged=lambda: True,
        authority={"github_owner_id": 12, "github_repository_id": 34})
    result = runner.run_post_delivery_login(delivery_root="unused", private_paths={},
        source_sha="f" * 40, ci_run_id=42, source_validator=lambda _: None,
        protection_reader=lambda **_: (12, 34), accepted_loader=lambda **_: evidence,
        bundle_factory=lambda: pytest.fail("SDK before valid clock"), clock=lambda: now)
    assert result == {"ok": False, "category": "owner_enrolled_login_unverified", "calls": 0}


def test_cli_has_no_key_password_or_token_argument(capsys):
    with pytest.raises(SystemExit) as exc:
        runner.main(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--delivery-root" in help_text
    assert "--password" not in help_text
    assert "--token" not in help_text
