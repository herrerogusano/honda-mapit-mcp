from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import run_dev_owner_enrolled_login as runner


ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
PRIVATE_PATHS = {
    name: f"C:/private/{name}.json"
    for name in runner._PRIVATE_INPUT_FIELDS
}


def _evidence():
    update_state = {
        "binding": {"client_request_token": "owner-enrolled-test"},
        "phase": "accepted",
        "receipt": {"runtime_evidence_sha256": "a" * 64},
    }
    return SimpleNamespace(
        assert_unchanged=lambda: True,
        authority={"account_id": ACCOUNT, "operator_arn": OPERATOR,
                   "github_owner_id": 7, "github_repository_id": 8},
        accepted={"accepted": True},
        update_state=update_state,
        binding={"accepted_binding": True},
        capsule={"capsule": True},
        private_inputs=SimpleNamespace(manifest_inputs={"context": object()},
                                       prior_template={"Resources": {}}),
        manifest_raw=b"{}", invitation_jwks=b"{}", mapit_jwks=b"{}", archive_bytes=b"zip",
    )


def _source_validator(events):
    def validate(_auth):
        events.append("source")
    return validate


def _protection_reader(events):
    def read(**_kwargs):
        events.append("protections")
        return 7, 8
    return read


def _runner(monkeypatch, *, events, evidence=None, clock=None, observer_call=None,
            jwks_fetcher=None, channel_factory=None, observer_factory=None,
            protection_reader=None):
    evidence = evidence or _evidence()
    clock_value = [1000.0]
    clock = clock or (lambda: clock_value[0])

    class Observer:
        last_read_call_count = 6

        def __call__(self, phase, binding):
            events.append("observer")
            assert phase == "accepted"
            assert binding == evidence.binding
            if observer_call is not None:
                return observer_call(self)
            return {"phase": "accepted"}

        def owner_login_projections(self, _readback):
            return {}, {}

    captured = {}

    def make_observer(**kwargs):
        events.append("observer_factory")
        captured.update(kwargs)
        return observer_factory(kwargs, Observer()) if observer_factory else Observer()

    class Channel:
        def __init__(self, _policy, _keys, consume):
            self.consume = consume

        def serve(self, *, ready_callback=None):
            events.append("serve")
            if ready_callback is not None:
                ready_callback("http://127.0.0.1:8787/")
            self.consume("opaque-verified-token")
            return "verified"

    def make_channel(policy, keys, consume):
        events.append("channel_factory")
        return channel_factory(policy, keys, consume) if channel_factory else Channel(policy, keys, consume)

    monkeypatch.setattr(runner, "validate_owner_enrolled_login_lineage",
                        lambda **_kwargs: SimpleNamespace(policy=object()))
    monkeypatch.setattr(runner, "parse_cognito_jwks", lambda _raw: object())
    result = runner.run_post_delivery_login(
        delivery_root="private-delivery-root", private_paths=PRIVATE_PATHS,
        source_sha="f" * 40, ci_run_id=90,
        source_validator=_source_validator(events),
        protection_reader=protection_reader or _protection_reader(events),
        accepted_loader=lambda **_kwargs: evidence,
        bundle_factory=lambda: events.append("bundle") or object(),
        observer_factory=make_observer,
        jwks_fetcher=jwks_fetcher or (lambda _policy: events.append("jwks") or b"jwks"),
        channel_factory=make_channel, clock=clock, monotonic=lambda: 1.0,
    )
    return result, events, captured, clock_value


def test_failed_accepted_observer_reports_bounded_attempted_calls(monkeypatch):
    events = []

    def fail_after_reads(observer):
        observer.last_read_call_count = 13
        raise RuntimeError("provider detail must not escape")

    result, _events, _captured, _clock_value = _runner(
        monkeypatch, events=events, observer_call=fail_after_reads)
    assert result == {"ok": False, "category": "owner_enrolled_login_unverified", "calls": 13}
    assert "provider detail" not in repr(result)


def test_exact_accepted_update_state_is_passed_into_registered_observer(monkeypatch):
    events = []
    result, _events, captured, _clock_value = _runner(monkeypatch, events=events)
    assert result["ok"] is True, events
    assert captured["accepted_update_state"] is not None
    assert captured["accepted_update_state"]["phase"] == "accepted"
    assert captured["accepted_update_state"]["receipt"]["runtime_evidence_sha256"] == "a" * 64


def test_fresh_observation_expiry_during_jwks_fetch_prevents_listener(monkeypatch):
    events = []
    clock_value = [1000.0]

    def slow_jwks(_policy):
        events.append("jwks")
        clock_value[0] = 1599.0  # the observation window end is exclusive
        return b"jwks"

    result, events, _captured, _clock_value = _runner(
        monkeypatch, events=events, clock=lambda: clock_value[0], jwks_fetcher=slow_jwks)
    assert result == {"ok": False, "category": "owner_enrolled_login_unverified", "calls": 6}
    assert "channel_factory" not in events
    assert "serve" not in events


def test_source_and_protection_gates_repeat_after_jwks_before_listener(monkeypatch):
    events = []
    result, events, _captured, _clock_value = _runner(monkeypatch, events=events)
    assert result == {"ok": True, "category": "owner_enrolled_login_verified", "calls": 6}
    jwks_index = events.index("jwks")
    channel_index = events.index("channel_factory")
    assert events[jwks_index + 1:channel_index] == ["source", "protections"]
    assert events[channel_index + 1] == "serve"


def test_window_expiry_during_final_protection_gate_prevents_listener(monkeypatch):
    events = []
    clock_value = [1000.0]
    protection_reads = 0

    def protections(**_kwargs):
        nonlocal protection_reads
        protection_reads += 1
        events.append("protections")
        if protection_reads == 4:
            # The fourth protection read is the final fresh gate after JWKS.
            clock_value[0] = 1599.0
        return 7, 8

    result, events, _captured, _clock_value = _runner(
        monkeypatch, events=events, clock=lambda: clock_value[0],
        protection_reader=protections)
    assert result == {"ok": False, "category": "owner_enrolled_login_unverified", "calls": 6}
    assert "channel_factory" not in events
    assert "serve" not in events
