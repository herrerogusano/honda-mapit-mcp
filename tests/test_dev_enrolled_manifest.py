import hashlib
import json
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from test_aws_dev_multiuser_entrypoint import _bundle
from test_identity_binding import NOW, _config

ACCOUNT = "123456789012"


def _manifest():
    invitation = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mapit = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    legacy_raw, invitation_jwks, _ = _bundle(invitation)
    _, mapit_jwks, _ = _bundle(mapit)
    legacy = json.loads(legacy_raw)
    config = asdict(_config())
    del config["email"], config["password"]
    document = {
        "schema": 1, "builder": "build_dev_enrolled_archive", "environment": "dev",
        "mode": "mapit-enrolled", "source_sha": "1" * 40,
        "api_id": legacy["api_id"], "user_pool_id": legacy["user_pool_id"], "client_id": legacy["client_id"],
        "invitation_jwks_sha256": hashlib.sha256(invitation_jwks).hexdigest(),
        "mapit_jwks_sha256": hashlib.sha256(mapit_jwks).hexdigest(),
        "authorization_table_arn": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
        "binding_table_arn": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-mapit-identity-bindings",
        "key_parameter_path": "/honda-mapit-mcp/dev/mapit-identity-binding-config",
        "key_publication_start_epoch": int(NOW.timestamp()) - 1,
        "key_publication_end_epoch": int(NOW.timestamp()) + 3599,
        "mapit_config": config,
        "tenants": [{"key": item["key"], "subject": item["subject"]} for item in legacy["tenants"]],
    }
    return document, invitation_jwks, mapit_jwks


def _parse(document, invitation, mapit):
    raw = json.dumps(document, separators=(",", ":")).encode()
    return parse_enrolled_dev_manifest(raw, invitation, mapit,
        expected_digest=hashlib.sha256(raw).hexdigest(), account_id=ACCOUNT)


def test_manifest_pins_two_independent_verifiers_and_no_secrets():
    document, invitation, mapit = _manifest()
    parsed = _parse(document, invitation, mapit)
    assert len(parsed.policies) == 2 and parsed.config.password is None
    assert dict(parsed.invitation_keys) != dict(parsed.mapit_keys)
    with pytest.raises(TypeError):
        parsed.policies["changed"] = object()
    assert repr(parsed) == "EnrolledDevManifest(<redacted>)"


@pytest.mark.parametrize("field,value", [
    ("environment", "prod"), ("schema", True), ("mode", "synthetic"),
    ("source_sha", "0" * 40),
    ("binding_table_arn", f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"),
    ("key_parameter_path", "/honda-mapit-mcp/dev/identity-binding-config"),
    ("tenants", []),
])
def test_wrong_context_or_legacy_storage_is_rejected(field, value):
    document, invitation, mapit = _manifest()
    document[field] = value
    with pytest.raises(ValueError, match="^dev_enrolled_manifest_invalid$"):
        _parse(document, invitation, mapit)


def test_duplicate_subject_keys_or_configuration_secrets_are_rejected():
    for variant in ("subject", "key", "password", "public_keys_swapped"):
        document, invitation, mapit = _manifest()
        if variant in {"subject", "key"}:
            document["tenants"][1][variant] = document["tenants"][0][variant]
        elif variant == "password":
            document["mapit_config"]["password"] = "synthetic-secret-canary"
        else:
            invitation, mapit = mapit, invitation
        with pytest.raises(ValueError, match="^dev_enrolled_manifest_invalid$"):
            _parse(document, invitation, mapit)


def test_duplicate_json_and_wrong_outer_digest_fail_closed():
    document, invitation, mapit = _manifest()
    raw = json.dumps(document, separators=(",", ":")).encode()
    duplicate = raw.replace(b'"schema":1,', b'"schema":1,"schema":1,')
    for candidate, digest in ((duplicate, hashlib.sha256(duplicate).hexdigest()), (raw, "0" * 64)):
        with pytest.raises(ValueError, match="^dev_enrolled_manifest_invalid$"):
            parse_enrolled_dev_manifest(candidate, invitation, mapit, expected_digest=digest, account_id=ACCOUNT)
