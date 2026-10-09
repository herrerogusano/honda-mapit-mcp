from __future__ import annotations

import base64
import json

from scripts import check_aws_templates as checker


def test_owner_enrolled_schema_fixture_uses_only_synthetic_public_jwks(monkeypatch):
    from scripts import dev_owner_enrolled_runtime as profile

    captured = {}
    original = profile.build_owner_enrolled_dev_runtime_target

    def capture(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(profile, "build_owner_enrolled_dev_runtime_target", capture)
    documents = checker.fixed_documents()
    target = json.loads(documents["retained_dev_owner_enrolled_runtime"])

    assert set(captured) == {
        "prior_template", "mapit_bootstrap_template", "manifest_raw", "invitation_jwks",
        "mapit_jwks", "manifest_sha256", "account_id", "source_sha", "zip_sha256",
        "execution_start_epoch", "execution_end_epoch",
    }
    jwks_sets = []
    for name in ("invitation_jwks", "mapit_jwks"):
        raw = captured[name]
        jwks = json.loads(raw)
        assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert set(key) == {"kid", "kty", "alg", "use", "n", "e"}
        assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["use"] == "sig"
        modulus = base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4))
        assert len(modulus) == 256
        jwks_sets.append((key["kid"], modulus))
        assert raw.decode("ascii") not in documents["retained_dev_owner_enrolled_runtime"]
    assert jwks_sets[0][0] != jwks_sets[1][0]
    assert jwks_sets[0][1] != jwks_sets[1][1]

    resources = target["Resources"]
    assert len(resources) == 19
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert resources["McpUserPool"] == captured["prior_template"]["Resources"]["McpUserPool"]
    assert resources["McpUserPoolClient"] == captured["prior_template"]["Resources"]["McpUserPoolClient"]
    assert target["Metadata"]["NotDeployReady"] is True
    assert target["Metadata"]["HistoricalSyntheticUsersAuthenticateAfterIssuerSwitch"] is False


def test_owner_enrolled_checker_document_is_registered_once_in_static_inventory():
    documents = checker.fixed_documents()
    assert list(label for label in documents if label == "retained_dev_owner_enrolled_runtime") == [
        "retained_dev_owner_enrolled_runtime"
    ]
    target = json.loads(documents["retained_dev_owner_enrolled_runtime"])
    assert target["Metadata"]["Readiness"] == "RETAINED_DEV_OWNER_ENROLLED_NOT_DEPLOY_READY"
    assert target["Metadata"]["APIEndpointRemainsDisabled"] is True
    assert target["Metadata"]["LambdaReservedConcurrencyRemainsZero"] is True
