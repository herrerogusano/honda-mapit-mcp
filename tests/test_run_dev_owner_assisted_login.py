import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_dev_owner_assisted_login as runner
from test_dev_owner_login_context import receipt, parse


def owner_receipt():
    parts = receipt()
    policy = parts[3]
    manifest = {"environment": "prod", "region": "eu-west-1", "account_id": parts[0]["account"],
        **{name: getattr(policy, name) for name in ("user_pool_id", "api_id", "client_id", "owner_subject")}}
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return {"schema": 1, "kind": "cd_delivery_preparation",
        "inventory": {"account": parts[0]["account"], "manifest": manifest, "manifest_sha": digest},
        "final_release_verified": {"exact_readback_verified": True, "manifest_sha256": digest}}


def test_owner_identity_is_loaded_from_private_accepted_release_not_callback(tmp_path):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(owner_receipt()))
    assert runner.load_trusted_owner_policy(path, expected_account="123456789012", acl_checker=lambda _: True) == receipt()[3]


@pytest.mark.parametrize("change", ["account", "digest", "accepted", "subject", "duplicate", "acl"])
def test_invalid_owner_receipt_fails_redacted(tmp_path, change):
    doc = owner_receipt()
    if change == "account":
        doc["inventory"]["account"] = "999999999999"
    elif change == "digest":
        doc["inventory"]["manifest_sha"] = "0" * 64
    elif change == "accepted":
        doc["final_release_verified"]["exact_readback_verified"] = False
    elif change == "subject":
        doc["inventory"]["manifest"]["owner_subject"] = "callback-claim"
    raw = json.dumps(doc)
    if change == "duplicate":
        raw = raw.replace('"schema": 1', '"schema": 1, "schema": 1')
    path = tmp_path / "receipt.json"
    path.write_text(raw)
    with pytest.raises(ValueError, match="^owner_login_context_unverified$"):
        runner.load_trusted_owner_policy(path, expected_account="123456789012", acl_checker=lambda _: change != "acl")


class Response:
    status = 200
    def __init__(self, raw):
        self.raw = raw
        self.closed = False
    def read(self, size):
        value, self.raw = self.raw[:size], self.raw[size:]
        return value
    def close(self):
        self.closed = True


def test_public_keys_fetch_uses_exact_pinned_issuer_and_single_direct_get():
    policy = receipt()[3]
    calls = []
    response = Response(b'{"keys":[]}')
    def open(request, *, timeout):
        calls.append(request.full_url)
        assert request.method == "GET" and timeout == 3
        return response
    assert runner.fetch_owner_public_jwks(policy, opener=SimpleNamespace(open=open)) == b'{"keys":[]}'
    assert calls == [policy.issuer_url + "/.well-known/jwks.json"]
    assert response.closed


def test_redirect_keys_fetch_never_follows_or_accepts_response():
    response = Response(b"sensitive diagnostic")
    response.status = 302
    with pytest.raises(ValueError, match="^owner_login_context_unverified$"):
        runner.fetch_owner_public_jwks(receipt()[3], opener=SimpleNamespace(open=lambda *_a, **_k: response))
    assert response.closed


def test_runner_passes_current_source_and_memory_consumer_without_bootstrap(monkeypatch):
    parts = receipt()
    accepted = parse(parts)
    original = copy.deepcopy(parts[:3])
    monkeypatch.setattr(runner, "validate_private_location", lambda path, **_: Path(path))
    monkeypatch.setattr(runner, "load_authorization", lambda _: parts[0])
    monkeypatch.setattr(runner, "_load_binding", lambda *_a, **_k: parts[1])
    monkeypatch.setattr(runner, "FileJournal", lambda _: SimpleNamespace(load=lambda: parts[2]))
    monkeypatch.setattr(runner, "load_trusted_owner_policy", lambda *_a, **_k: parts[3])
    monkeypatch.setattr(runner, "OwnerOAuthSdkBindings", lambda *_a, **_k: SimpleNamespace(calls=23))
    events = []
    def source(auth):
        assert auth["source_sha"] == "d" * 40 and auth["ci_run_id"] == 789
        events.append("source")
    token = object()
    def prepare(ctx, sdk, **kwargs):
        assert ctx == accepted and kwargs["public_jwks"] == b"public"
        def serve(*, ready_callback=None):
            ready_callback("http://127.0.0.1:8787/")
            kwargs["token_consumer"](token)
            return "verified"
        return SimpleNamespace(serve=serve)
    result = runner.run_login(Path("private/authorization.json"), Path("release.json"),
        source_sha="d" * 40, ci_run_id=789, client_factory=lambda: {}, source_validator=source,
        protection_reader=lambda **_: (1, 2), jwks_fetcher=lambda _: b"public", channel_preparer=prepare,
        token_consumer=lambda value: events.append(value is token), ready_callback=lambda url: events.append(url))
    assert result == {"ok": True, "category": "owner_login_verified", "calls": 23}
    assert events == ["source", "http://127.0.0.1:8787/", True]
    assert parts[:3] == original


def test_runner_source_failure_before_sdk_or_public_network(monkeypatch):
    parts = receipt()
    monkeypatch.setattr(runner, "validate_private_location", lambda path, **_: Path(path))
    monkeypatch.setattr(runner, "load_authorization", lambda _: parts[0])
    monkeypatch.setattr(runner, "_load_binding", lambda *_a, **_k: parts[1])
    monkeypatch.setattr(runner, "FileJournal", lambda _: SimpleNamespace(load=lambda: parts[2]))
    monkeypatch.setattr(runner, "load_trusted_owner_policy", lambda *_a, **_k: parts[3])
    def fail(_):
        raise ValueError("sensitive CI error")
    result = runner.run_login(Path("private/authorization.json"), Path("release.json"),
        source_sha="d" * 40, ci_run_id=789, source_validator=fail,
        client_factory=lambda: pytest.fail("SDK constructed"), jwks_fetcher=lambda _: pytest.fail("HTTP called"))
    assert result == {"ok": False, "category": "owner_login_unverified", "calls": 0}
