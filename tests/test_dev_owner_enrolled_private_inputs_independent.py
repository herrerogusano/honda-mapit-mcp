from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import dev_owner_enrolled_private_inputs as loader
from scripts.run_aws_closed_rehearsal import FileJournal
from test_dev_owner_enrolled_private_inputs import _canonical, _private_inputs, _write


def _all_private_file_bytes(inputs):
    files = set()
    for value in inputs.values():
        if isinstance(value, Path):
            if value.is_file():
                files.add(value.resolve())
            elif value.is_dir():
                files.update(path.resolve() for path in value.rglob("*") if path.is_file())
    return {path: path.read_bytes() for path in files}


def test_loader_fetches_only_two_exact_issuer_jwks_and_does_not_mutate_inputs(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    before = _all_private_file_bytes(inputs)
    original_fetcher = inputs["jwks_fetcher"]
    requests = []

    def recording_fetcher(url):
        requests.append(url)
        return original_fetcher(url)

    inputs["jwks_fetcher"] = recording_fetcher
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    config = json.loads(before[inputs["public_config_path"].resolve()])
    owner_binding = json.loads(before[inputs["owner_oauth_binding_path"].resolve()])
    expected = [
        loader._issuer_jwks_url(
            f"https://cognito-idp.eu-west-1.amazonaws.com/{owner_binding['owner_pool_id']}"),
        loader._issuer_jwks_url(
            f"https://cognito-idp.eu-west-1.amazonaws.com/{config['user_pool_id']}"),
    ]
    assert requests == expected
    assert len(requests) == 2
    assert _all_private_file_bytes(inputs) == before
    assert loaded.assert_unchanged() is True


def test_acl_failure_is_rejected_before_any_public_jwks_fetch(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    requests = []
    inputs["acl_checker"] = lambda _path: False
    inputs["jwks_fetcher"] = lambda url: requests.append(url)

    with pytest.raises(loader.PrivateInputsError):
        loader.load_owner_enrolled_private_inputs(**inputs)
    assert requests == []


def test_private_input_object_cannot_be_registered_by_direct_construction():
    projection = {
        "manifest_inputs": {}, "prior_template": {}, "runtime_binding": {},
        "bootstrap_template": {},
    }
    digest = hashlib.sha256(_canonical(projection)).hexdigest()
    forged = loader.OwnerEnrolledPrivateInputs(
        manifest_inputs={}, prior_template={}, runtime_binding={}, bootstrap_template={},
        fingerprints=(), max_sizes={}, acl_checker=lambda _path: True,
        object_digest=digest,
    )
    assert loader._REGISTERED.get(forged) is None
    assert forged.assert_unchanged() is False


def test_returned_object_cannot_disable_file_fingerprint_rechecks(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    path = inputs["public_config_path"]
    value = json.loads(path.read_bytes())
    value["discovery_enabled"] = not value["discovery_enabled"]
    path.write_bytes(_canonical(value))

    # Mutable fields on the returned instance must not be the source of truth
    # for its trust baseline.
    loaded._fingerprints = ()
    assert loaded.assert_unchanged() is False


def test_equal_subclass_cannot_borrow_registered_projection_baseline(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)

    class EqualProjection(loader.OwnerEnrolledPrivateInputs):
        def __hash__(self):
            return hash(loaded)

        def __eq__(self, other):
            return other is loaded

    counterfeit = object.__new__(EqualProjection)
    counterfeit.manifest_inputs = loaded.manifest_inputs
    counterfeit.prior_template = loaded.prior_template
    counterfeit.runtime_binding = loaded.runtime_binding
    counterfeit.bootstrap_template = loaded.bootstrap_template
    assert counterfeit is not loaded
    assert counterfeit.assert_unchanged() is False


def test_owner_oauth_state_directory_must_match_the_supplied_journal(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    original_state = inputs["owner_oauth_state_dir"]
    alternate_root = tmp_path / "alternate-owner"
    alternate_root.mkdir()
    alternate_state = alternate_root / "state"
    alternate_state.mkdir()
    original_journal = FileJournal(original_state).load()
    FileJournal(alternate_state).save(copy.deepcopy(original_journal))

    binding = json.loads(inputs["owner_oauth_binding_path"].read_bytes())
    binding["state_directory"] = str(alternate_state.resolve())
    alternate_binding = _write(alternate_root / "owner-oauth-binding.json", binding)
    inputs["owner_oauth_binding_path"] = alternate_binding
    # The binding parser accepts its own sibling state directory, while the
    # loader is deliberately pointed at the original owner's state directory.
    inputs["owner_oauth_state_dir"] = original_state

    with pytest.raises(loader.PrivateInputsError):
        loader.load_owner_enrolled_private_inputs(**inputs)


def test_runtime_bundle_must_match_the_bootstrap_authority_digest(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    bundle = json.loads(inputs["mapit_evidence_path"].read_bytes())
    bundle["runtime_binding"]["api_id"] = "foreign-api-id"
    inputs["mapit_evidence_path"].write_bytes(_canonical(bundle))

    with pytest.raises(loader.PrivateInputsError):
        loader.load_owner_enrolled_private_inputs(**inputs)


def test_input_modified_during_second_jwks_fetch_fails_closed(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    original_fetcher = inputs["jwks_fetcher"]
    requests = []

    def mutating_fetcher(url):
        requests.append(url)
        result = original_fetcher(url)
        if len(requests) == 2:
            path = inputs["public_config_path"]
            config = json.loads(path.read_bytes())
            config["discovery_enabled"] = not config["discovery_enabled"]
            path.write_bytes(_canonical(config))
        return result

    inputs["jwks_fetcher"] = mutating_fetcher
    with pytest.raises(loader.PrivateInputsError):
        loader.load_owner_enrolled_private_inputs(**inputs)
    assert len(requests) == 2


def test_fetcher_rejects_clock_rollback_between_body_chunks(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    # Reuse the fixture's valid public JWKS without invoking the loader's
    # injected callback, then exercise only the direct bounded transport.
    owner_binding = json.loads(inputs["owner_oauth_binding_path"].read_bytes())
    valid_jwks = inputs["jwks_fetcher"](
        loader._issuer_jwks_url(
            f"https://cognito-idp.eu-west-1.amazonaws.com/{owner_binding['owner_pool_id']}"))

    class Response:
        status = 200

        def __init__(self):
            self.body = valid_jwks
            self.closed = False

        def read1(self, amount):
            chunk, self.body = self.body[:amount], self.body[amount:]
            return chunk

        def close(self):
            self.closed = True

    class Opener:
        def __init__(self, response):
            self.response = response
            self.calls = []

        def open(self, request, *, timeout):
            self.calls.append((request, timeout))
            return self.response

    response = Response()
    opener = Opener(response)
    samples = iter((10.0, 15.0, 14.0))
    with pytest.raises(ValueError):
        loader._fetch_jwks(
            loader._issuer_jwks_url(
                f"https://cognito-idp.eu-west-1.amazonaws.com/{owner_binding['owner_pool_id']}"),
            opener=opener, monotonic=lambda: next(samples))
    assert response.closed is True
    assert len(opener.calls) == 1
    assert opener.calls[0][1] == 3


@pytest.mark.parametrize("status,body", [(503, b"failure"), (200, b"x" * (32 * 1024 + 1))],
                         ids=["bad-status", "oversized-body"])
def test_fetcher_closes_response_for_bad_status_or_oversized_body(tmp_path, status, body):
    inputs, _fixture = _private_inputs(tmp_path)
    owner_binding = json.loads(inputs["owner_oauth_binding_path"].read_bytes())
    valid_url = loader._issuer_jwks_url(
        f"https://cognito-idp.eu-west-1.amazonaws.com/{owner_binding['owner_pool_id']}")

    class Response:
        def __init__(self):
            self.status = status
            self.body = body
            self.closed = False

        def read1(self, amount):
            chunk, self.body = self.body[:amount], self.body[amount:]
            return chunk

        def close(self):
            self.closed = True

    class Opener:
        def __init__(self, response):
            self.response = response
            self.calls = 0

        def open(self, request, *, timeout):
            assert request.full_url == valid_url
            assert request.get_method() == "GET"
            assert timeout == 3
            self.calls += 1
            return self.response

    response = Response()
    opener = Opener(response)
    with pytest.raises(Exception):
        loader._fetch_jwks(valid_url, opener=opener, monotonic=lambda: 1.0)
    assert response.closed is True
    assert opener.calls == 1


def test_fetcher_rejects_non_cognito_url_before_opening():
    class Opener:
        calls = 0

        def open(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("must not open an untrusted URL")

    opener = Opener()
    with pytest.raises(ValueError):
        loader._fetch_jwks("https://attacker.example/jwks.json", opener=opener)
    assert opener.calls == 0
