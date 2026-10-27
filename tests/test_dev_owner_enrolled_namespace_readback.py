from datetime import datetime, timezone

import pytest

from scripts.dev_owner_enrolled_namespace_readback import verify_published_namespace
from scripts.run_dev_mapit_binding_key_setup import CONFIG_PARAMETER, OPERATOR_ROLE_NAME, _verify_current_bootstrap
from tests.test_dev_owner_invitation_bootstrap_reads import _fixture


def _published():
    coordinator, state, guard, digest = _fixture()
    authority = coordinator.authority
    publication = {"schema": 1, "operation": "dev_mapit_binding_key_publication",
        "namespace": "mapit", "account": authority.account_id, "source": "9" * 40,
        "run_id": authority.run_id + 1, "bootstrap_sha256": digest,
        "parameter_path": CONFIG_PARAMETER, "start": authority.authorized_from_epoch,
        "end": authority.authorized_from_epoch + 600, "phase": "accepted"}
    row = {"Name": CONFIG_PARAMETER, "Type": "SecureString", "Version": 1,
        "Tier": "Standard", "DataType": "text", "KeyId": "alias/aws/ssm", "Policies": [],
        "LastModifiedDate": datetime.fromtimestamp(publication["start"] + 1, timezone.utc),
        "LastModifiedUser": f"arn:aws:sts::{authority.account_id}:assumed-role/{OPERATOR_ROLE_NAME}/mapit-key-{publication['run_id']}"}
    requests = []
    def describe(**kwargs):
        requests.append(kwargs)
        return {"Parameters": [row], "ResponseMetadata": {"HTTPStatusCode": 200}}
    coordinator.clients["ssm"].describe_parameters = describe
    return coordinator, state, guard, digest, publication, row, requests


def _run(fixture):
    coordinator, state, guard, digest, publication, _row, _requests = fixture
    return verify_published_namespace(guard.wrap(), coordinator.authority, state,
        coordinator.plan, digest, publication, [0], 100, 150, lambda: 100.0)


def test_published_namespace_composes_actual_resource_verifier_without_key_reads():
    fixture = _published()
    coordinator, state, guard, _digest, _pub, _row, requests = fixture
    ssm = coordinator.clients["ssm"]
    original = ssm.get_parameter
    read_paths = []
    def get(**kwargs):
        read_paths.append(kwargs)
        return original(**kwargs)
    ssm.get_parameter = get
    assert _run(fixture) == {"verified": True, "config_version": 1,
        "table_id": state["readback_receipt"]["table_id"], "binding_empty": True,
        "sessions_absent": True}
    assert requests == [{"ParameterFilters": [{"Key": "Name", "Option": "Equals",
        "Values": [CONFIG_PARAMETER]}], "MaxResults": 5}]
    assert read_paths and all(p["Name"] != CONFIG_PARAMETER and p["WithDecryption"] is False for p in read_paths)
    assert guard.write_dispatch_started is False


@pytest.mark.parametrize("change", [
    lambda row, pub: row.update(Version=True),
    lambda row, pub: row.update(Version=2),
    lambda row, pub: row.update(Type="String"),
    lambda row, pub: row.update(KeyId="alias/other"),
    lambda row, pub: row.update(LastModifiedUser="another-operator"),
    lambda row, pub: row.update(LastModifiedDate=datetime.fromtimestamp(pub["end"], timezone.utc)),
    lambda row, pub: row.update(Policies=[{"PolicyType": "Expiration"}]),
])
def test_published_metadata_drift_is_rejected(change):
    fixture = _published()
    change(fixture[5], fixture[4])
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)
    assert fixture[2].write_dispatch_started is False


def test_pending_publication_never_dispatches_metadata_or_resource_reads():
    fixture = _published()
    fixture[4]["phase"] = "put_intent"
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)
    assert fixture[2].calls == 0


def test_original_prepublication_contract_still_rejects_present_config():
    coordinator, state, guard, digest, _pub, _row, _requests = _published()
    original = coordinator.clients["ssm"].get_parameter
    def get(**kwargs):
        if kwargs["Name"] == CONFIG_PARAMETER:
            return {"Parameter": {"Name": CONFIG_PARAMETER}, "ResponseMetadata": {"HTTPStatusCode": 200}}
        return original(**kwargs)
    coordinator.clients["ssm"].get_parameter = get
    with pytest.raises(ValueError):
        _verify_current_bootstrap(guard.wrap(), coordinator.authority, state,
            coordinator.plan, digest, [0], 100, 150, lambda: 100.0)
