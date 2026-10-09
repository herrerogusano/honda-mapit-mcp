from __future__ import annotations

import copy
import base64
import hashlib
import json
import io
import zipfile
from contextlib import contextmanager

import pytest

from scripts.dev_owner_enrolled_delivery import (
    OwnerEnrolledClosedDelivery,
    OwnerEnrolledDeliveryError,
)
from scripts.dev_owner_enrolled_runtime import build_owner_enrolled_dev_runtime_target
from mapit.dev_enrolled_manifest import MANIFEST_FILENAME, INVITATION_JWKS_FILENAME, MAPIT_JWKS_FILENAME
from test_dev_owner_enrolled_runtime import (
    ACCOUNT, API_ID, BUCKET, CALLBACK, OLD_KEYS, OLD_SOURCE, OLD_SUBJECTS, OWNER_CLIENT,
    OWNER_KEY, OWNER_POOL, OWNER_SUBJECT, START, _inputs,
)


class Journal:
    def __init__(self):
        self.state = None

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)


def _sha(ch: str) -> str:
    return ch * 64


def _authority(prior):
    return {
        "schema": 1,
        "kind": "dev-owner-enrolled-delivery",
        "account_id": ACCOUNT,
        "operator_arn": f"arn:aws:iam::{ACCOUNT}:user/dev-operator",
        "source_sha": "8" * 40,
        "ci_run_id": 108,
        "run_id": "abcdef0123456789abcdef0123456789",
        "authorized_from_epoch": START,
        "authorized_until_epoch": START + 600,
        "stack_id": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001",
        "service_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
        "artifact_bucket": BUCKET,
        "owner_context_sha256": _sha("1"),
        "owner_pool_id": OWNER_POOL,
        "owner_client_id": OWNER_CLIENT,
        "owner_resource_uri": f"https://{API_ID}.execute-api.eu-west-1.amazonaws.com/mcp",
        "owner_oauth_receipt_sha256": _sha("2"),
        "mapit_bootstrap_authority_sha256": _sha("3"),
        "mapit_bootstrap_receipt_sha256": _sha("4"),
        "mapit_table_id": "11111111-1111-4111-8111-111111111111",
        "invitation_receipt_sha256": _sha("5"),
        "key_publication_receipt_sha256": _sha("6"),
        "owner_tenant_key": OWNER_KEY,
        "mapit_config_path": "/honda-mapit-mcp/dev/mapit-identity-binding-config",
        "mapit_config_version": 1,
        "runtime_evidence_sha256": _sha("7"),
        "historical_tenant_keys": list(OLD_KEYS),
        "github_owner_id": 7,
        "github_repository_id": 8,
        "manifest_sha256": _sha("9"),
        "invitation_jwks_sha256": _sha("a"),
        "mapit_jwks_sha256": _sha("b"),
        "prior_template_sha256": hashlib.sha256(json.dumps(prior, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest(),
        "execution_start_epoch": START + 20,
        "execution_end_epoch": START + 320,
        "prior_zip_sha256": "1" * 64,
    }


def _accepted(auth):
    return {
        "owner_oauth": {"status": "accepted", "receipt_sha256": auth["owner_oauth_receipt_sha256"],
                        "account_id": ACCOUNT, "pool_id": OWNER_POOL, "client_id": OWNER_CLIENT,
                        "resource_uri": auth["owner_resource_uri"], "scope": auth["owner_resource_uri"] + "/use"},
        "mapit_bootstrap": {"status": "accepted", "receipt_sha256": auth["mapit_bootstrap_receipt_sha256"],
                            "authority_sha256": auth["mapit_bootstrap_authority_sha256"], "account_id": ACCOUNT,
                            "tenant_key": OWNER_KEY, "table_id": auth["mapit_table_id"]},
        "invitation": {"status": "accepted", "receipt_sha256": auth["invitation_receipt_sha256"],
                       "account_id": ACCOUNT, "table_name": "honda-mapit-mcp-dev-tenants",
                       "tenant_key": OWNER_KEY, "revision": 1},
        "key_publication": {"status": "accepted", "receipt_sha256": auth["key_publication_receipt_sha256"],
                            "account_id": ACCOUNT, "parameter_path": auth["mapit_config_path"], "version": 1},
    }


class Harness:
    def __init__(self):
        self.wall = START + 10
        self.mono = 50.0
        self.publish_calls = 0
        self.update_calls = 0
        self.current_calls = []
        self.fail_publish = False
        self.fail_update = False
        prior, bootstrap, args = _inputs()
        self.prior, self.bootstrap = prior, bootstrap
        self.args = args
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            for name, value in ((MANIFEST_FILENAME, args["manifest_raw"]),
                                (INVITATION_JWKS_FILENAME, args["invitation_jwks"]),
                                (MAPIT_JWKS_FILENAME, args["mapit_jwks"])):
                archive.writestr("mapit/" + name, value)
        self.archive = archive_buffer.getvalue()
        self.auth = _authority(prior)
        self.auth["prior_zip_sha256"] = "1" * 64
        self.auth["manifest_sha256"] = hashlib.sha256(args["manifest_raw"]).hexdigest()
        self.auth["invitation_jwks_sha256"] = hashlib.sha256(args["invitation_jwks"]).hexdigest()
        self.auth["mapit_jwks_sha256"] = hashlib.sha256(args["mapit_jwks"]).hexdigest()
        self.summary = {
            "zip_bytes": len(self.archive), "sha256": hashlib.sha256(self.archive).hexdigest(),
            "wheel_count": 28, "archive_entries": 100, "source_modules": 28,
            "public_key_count": 2, "dependencies_valid": True, "source_allowlist_valid": True,
            "lock_valid": True, "manifest_valid": True,
        }
        self.artifact_journal, self.update_journal = Journal(), Journal()
        self.coordinator = OwnerEnrolledClosedDelivery(
            authority=self.auth, accepted=_accepted(self.auth), prior_template=prior,
            mapit_bootstrap_template=bootstrap, manifest_raw=args["manifest_raw"],
            invitation_jwks=args["invitation_jwks"], mapit_jwks=args["mapit_jwks"],
            archive_bytes=self.archive, archive_summary=self.summary,
            artifact_journal=self.artifact_journal, update_journal=self.update_journal,
            source_check=self.source_check, protection_check=self.protection_check,
            current_state=self.state, publish_once=self.publish, update_once=self.update,
            clock=self.clock, monotonic=self.monotonic_clock,
        )

    def clock(self):
        return self.wall

    def monotonic_clock(self):
        return self.mono

    def source_check(self, binding):
        return {"source_sha": binding["source_sha"], "ci_run_id": binding["ci_run_id"],
                "head_sha": binding["source_sha"], "checks_passed": True}

    def protection_check(self, binding):
        return {"owner_id": binding["github_owner_id"],
                "repository_id": binding["github_repository_id"], "dev_environment_protected": True}

    def state(self, phase, binding):
        self.current_calls.append(phase)
        accepted = phase == "accepted"
        target = self.coordinator.target if hasattr(self, "coordinator") else build_owner_enrolled_dev_runtime_target(
            prior_template=self.prior, mapit_bootstrap_template=self.bootstrap,
            **{key: value for key, value in self.args.items() if key not in {"zip_sha256", "execution_start_epoch", "execution_end_epoch"}},
            manifest_sha256=self.auth["manifest_sha256"], account_id=ACCOUNT, source_sha=self.auth["source_sha"],
            zip_sha256=hashlib.sha256(self.archive).hexdigest(),
            execution_start_epoch=self.auth["execution_start_epoch"],
            execution_end_epoch=self.auth["execution_end_epoch"],
        )
        prior_hash = self.auth["prior_template_sha256"]
        target_hash = hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        issuer = target["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"] if accepted else self.prior["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"]
        checks = {name: True for name in {
            "stack_ownership", "resource_inventory", "api_disabled", "lambda_reserved_zero",
            "owner_oauth_current", "owner_jwt_authorizer", "handler_artifact", "authorization_row",
            "mapit_binding", "config_version_one", "role_policy_exact", "historical_synthetic_policy_preserved",
            "artifact_bucket_private",
        }} if accepted else {
            "stack_ownership": True, "resource_inventory": True, "api_disabled": True,
            "lambda_reserved_zero": True, "owner_oauth_current": True, "owner_jwt_authorizer": False,
            "handler_artifact": False, "authorization_row": True, "mapit_binding": True,
            "config_version_one": True, "role_policy_exact": True, "historical_synthetic_policy_preserved": True,
            "artifact_bucket_private": True,
        }
        return {
            "phase": phase, "account_id": ACCOUNT, "caller_arn": self.auth["operator_arn"],
            "stack_id": self.auth["stack_id"], "stack_status": "UPDATE_COMPLETE",
            "template_sha256": target_hash if accepted else prior_hash, "resource_count": 19,
            "api_disabled": True, "lambda_reserved_concurrency": 0,
            "handler_zip_sha256": hashlib.sha256(self.archive).hexdigest() if accepted else self.auth["prior_zip_sha256"],
            "owner_issuer": issuer, "owner_client_id": OWNER_CLIENT, "owner_tenant_key": OWNER_KEY,
            "authorization_table": "honda-mapit-mcp-dev-tenants", "authorization_row_status": "active",
            "authorization_row_revision": 1, "authorization_row_key": OWNER_KEY,
            "mapit_table_id": self.auth["mapit_table_id"], "mapit_config_path": self.auth["mapit_config_path"],
            "mapit_config_version": 1, "mapit_parameter_version": 1,
            "leading_keys": [*OLD_KEYS, OWNER_KEY] if accepted else list(OLD_KEYS),
            "owner_context_sha256": _sha("d") if accepted else self.auth["owner_context_sha256"],
            "owner_oauth_receipt_sha256": self.auth["owner_oauth_receipt_sha256"],
            "mapit_bootstrap_receipt_sha256": self.auth["mapit_bootstrap_receipt_sha256"],
            "invitation_receipt_sha256": self.auth["invitation_receipt_sha256"],
            "key_publication_receipt_sha256": self.auth["key_publication_receipt_sha256"],
            "runtime_evidence_sha256": _sha("c") if accepted else self.auth["runtime_evidence_sha256"],
            "runtime_checks": checks,
            "completion_event": ({"stack_id": self.auth["stack_id"], "resource_type": "AWS::CloudFormation::Stack",
                                  "status": "UPDATE_COMPLETE", "client_request_token": "owner-enrolled-" + self.auth["run_id"],
                                  "timestamp_epoch": START + 100, "response_http_status": 200,
                                  "matching_completion_events": 1} if accepted else None),
        }

    def publish(self, binding, archive):
        self.publish_calls += 1
        if self.fail_publish:
            raise RuntimeError("sensitive provider text")
        sha = hashlib.sha256(archive).hexdigest()
        return {"status": "verified", "bucket": BUCKET, "key": f"runtime/{sha}.zip", "sha256": sha,
                "size_bytes": len(archive), "expected_bucket_owner": ACCOUNT,
                "server_side_encryption": "AES256", "if_none_match": "*",
                "put_http_status": 200, "head_http_status": 200,
                "head_checksum_sha256": base64.b64encode(bytes.fromhex(sha)).decode("ascii"),
                "head_content_length": len(archive), "head_server_side_encryption": "AES256"}

    def update(self, stack_id, target, token, role):
        self.update_calls += 1
        if self.fail_update:
            raise RuntimeError("sensitive provider text")
        assert stack_id == self.auth["stack_id"]
        assert target == self.coordinator.target
        assert token == "owner-enrolled-" + self.auth["run_id"]
        assert role == self.auth["service_role_arn"]
        return {"status": "acknowledged", "http_status": 200, "stack_id": stack_id,
                "client_request_token": token, "target_template_sha256": self.coordinator.target_sha}


def test_positive_owner_delivery_rebuilds_target_and_stays_closed():
    h = Harness()
    assert h.coordinator.preflight() == {"ok": True, "phase": "ready"}
    assert h.coordinator.publish()["phase"] == "published"
    assert h.coordinator.update()["phase"] == "acknowledged"
    result = h.coordinator.readback()
    assert result == {"ok": True, "phase": "accepted", "api_disabled": True,
                      "lambda_reserved_concurrency": 0, "resource_count": 19,
                      "runtime_evidence_sha256": _sha("c")}
    assert h.publish_calls == h.update_calls == 1
    assert h.artifact_journal.state["phase"] == "published"
    assert h.update_journal.state["phase"] == "accepted"
    assert h.update_journal.state["receipt"]["runtime_evidence_sha256"] == _sha("c")
    assert all(call in h.current_calls for call in ("preflight", "pre_publish", "pre_update", "accepted"))


@pytest.mark.parametrize("mutation", [
    lambda a: a.update(owner_tenant_key=OLD_KEYS[0]),
    lambda a: a.update(mapit_config_version=2),
    lambda a: a.update(mapit_table_id="22222222-2222-4222-8222-222222222222"),
    lambda a: a.update(owner_client_id="OtherClient123456789"),
    lambda a: a.update(source_sha="7" * 40),
])
def test_binding_mismatches_rejected_before_journal_or_adapter(mutation):
    h = Harness()
    auth = copy.deepcopy(h.auth)
    mutation(auth)
    with pytest.raises(OwnerEnrolledDeliveryError):
        OwnerEnrolledClosedDelivery(
            authority=auth, accepted=_accepted(h.auth), prior_template=h.prior,
            mapit_bootstrap_template=h.bootstrap, manifest_raw=h.args["manifest_raw"],
            invitation_jwks=h.args["invitation_jwks"], mapit_jwks=h.args["mapit_jwks"],
            archive_bytes=h.archive, archive_summary=h.summary,
            artifact_journal=Journal(), update_journal=Journal(), source_check=h.source_check,
            protection_check=h.protection_check, current_state=h.state, publish_once=h.publish,
            update_once=h.update, clock=h.clock, monotonic=h.monotonic_clock)
    assert h.publish_calls == h.update_calls == 0


def test_accepted_invitation_must_be_owner_key_active_revision_one():
    h = Harness()
    accepted = _accepted(h.auth)
    accepted["invitation"]["revision"] = 2
    with pytest.raises(OwnerEnrolledDeliveryError, match="accepted_evidence_invalid"):
        OwnerEnrolledClosedDelivery(
            authority=h.auth, accepted=accepted, prior_template=h.prior,
            mapit_bootstrap_template=h.bootstrap, manifest_raw=h.args["manifest_raw"],
            invitation_jwks=h.args["invitation_jwks"], mapit_jwks=h.args["mapit_jwks"],
            archive_bytes=h.archive, archive_summary=h.summary,
            artifact_journal=Journal(), update_journal=Journal(), source_check=h.source_check,
            protection_check=h.protection_check, current_state=h.state, publish_once=h.publish,
            update_once=h.update, clock=h.clock, monotonic=h.monotonic_clock)


def test_ambiguous_artifact_publication_is_sticky_and_never_retried():
    h = Harness()
    h.coordinator.preflight()
    h.fail_publish = True
    with pytest.raises(OwnerEnrolledDeliveryError, match="artifact_write_unknown"):
        h.coordinator.publish()
    assert h.artifact_journal.state["phase"] == "intent"
    h.fail_publish = False
    with pytest.raises(OwnerEnrolledDeliveryError, match="journal_invalid"):
        h.coordinator.publish()
    assert h.publish_calls == 1
    assert h.update_calls == 0


def test_ambiguous_stack_update_is_sticky_and_readback_is_read_only():
    h = Harness()
    h.coordinator.preflight()
    h.coordinator.publish()
    h.fail_update = True
    with pytest.raises(OwnerEnrolledDeliveryError, match="update_write_unknown"):
        h.coordinator.update()
    assert h.update_journal.state["phase"] == "intent"
    h.fail_update = False
    with pytest.raises(OwnerEnrolledDeliveryError, match="journal_invalid"):
        h.coordinator.update()
    assert h.update_calls == 1


def test_source_protection_or_current_readback_failure_stops_before_writes():
    h = Harness()
    h.coordinator._source_check = lambda _binding: False
    with pytest.raises(OwnerEnrolledDeliveryError, match="source_ci_failed"):
        h.coordinator.preflight()
    assert h.publish_calls == h.update_calls == 0
    assert h.artifact_journal.state is None and h.update_journal.state is None


def test_post_intent_closed_state_is_rechecked_before_each_write():
    h = Harness()
    h.coordinator.preflight()
    original_state = h.coordinator._current_state
    phases = []

    def state(phase, binding):
        phases.append(phase)
        value = original_state(phase, binding)
        if phase == "pre_publish" and h.artifact_journal.state["phase"] == "intent":
            value["api_disabled"] = False
        return value

    h.coordinator._current_state = state
    with pytest.raises(OwnerEnrolledDeliveryError, match="current_state_unverified"):
        h.coordinator.publish()
    assert phases == ["pre_publish", "pre_publish"]
    assert h.publish_calls == 0
    assert h.artifact_journal.state["phase"] == "intent"


def test_target_mutation_after_construction_is_rejected_before_provider_calls():
    h = Harness()
    h.coordinator.target["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = False
    with pytest.raises(OwnerEnrolledDeliveryError, match="binding_invalid"):
        h.coordinator.preflight()
    assert h.publish_calls == h.update_calls == 0
    assert h.artifact_journal.state is None and h.update_journal.state is None


def test_completion_event_must_be_the_unique_exact_root_event():
    h = Harness()
    h.coordinator.preflight()
    h.coordinator.publish()
    h.coordinator.update()
    current = h.coordinator._current_state

    def bad_event(phase, binding):
        value = current(phase, binding)
        if phase == "accepted":
            value["completion_event"]["matching_completion_events"] = 2
        return value

    h.coordinator._current_state = bad_event
    with pytest.raises(OwnerEnrolledDeliveryError, match="current_state_unverified"):
        h.coordinator.readback()
    assert h.update_calls == 1
    assert h.update_journal.state["phase"] == "acknowledged"


def test_accepted_readback_rejects_open_api_or_changed_invitation():
    for field, changed in (("api_disabled", False), ("authorization_row_revision", 2),
                           ("mapit_parameter_version", 2)):
        h = Harness()
        h.coordinator.preflight()
        h.coordinator.publish()
        h.coordinator.update()
        current = h.coordinator._current_state

        def bad_state(phase, binding, *, current=current, field=field, changed=changed):
            value = current(phase, binding)
            if phase == "accepted":
                value[field] = changed
            return value

        h.coordinator._current_state = bad_state
        with pytest.raises(OwnerEnrolledDeliveryError, match="current_state_unverified"):
            h.coordinator.readback()
        assert h.update_calls == 1


def test_pending_update_is_read_only_and_keeps_closure_verified():
    h = Harness()
    h.coordinator.preflight()
    h.coordinator.publish()
    h.coordinator.update()
    current = h.coordinator._current_state

    def pending(phase, binding):
        value = current(phase, binding)
        if phase == "accepted":
            value["stack_status"] = "UPDATE_IN_PROGRESS"
            value["completion_event"] = None
        return value

    h.coordinator._current_state = pending
    assert h.coordinator.readback() == {"ok": True, "phase": "pending"}
    assert h.update_calls == 1
    assert h.update_journal.state["phase"] == "acknowledged"


def test_failed_expiry_check_is_sticky_even_if_wall_clock_moves_back():
    h = Harness()
    h.wall = h.auth["authorized_until_epoch"]
    with pytest.raises(OwnerEnrolledDeliveryError, match="window_closed"):
        h.coordinator.preflight()
    h.wall = h.auth["authorized_from_epoch"] + 1
    with pytest.raises(OwnerEnrolledDeliveryError, match="window_closed"):
        h.coordinator.preflight()
    assert h.publish_calls == h.update_calls == 0
    assert h.artifact_journal.state is None and h.update_journal.state is None
