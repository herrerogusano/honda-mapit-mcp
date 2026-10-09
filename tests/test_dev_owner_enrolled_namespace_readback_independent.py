from __future__ import annotations

from datetime import datetime, timezone

import pytest

from scripts.run_dev_mapit_binding_key_setup import CONFIG_PARAMETER
from test_dev_owner_enrolled_namespace_readback import _published, _run


def test_pagination_or_duplicate_parameter_rows_are_not_treated_as_complete_readback():
    for mutate in (
        lambda reply: reply.update(NextToken="opaque"),
        lambda reply: reply.update(Parameters=reply["Parameters"] * 2),
    ):
        fixture = _published()
        coordinator = fixture[0]
        ssm = coordinator.clients["ssm"]
        original = ssm.describe_parameters
        def malformed(**kwargs):
            reply = original(**kwargs)
            mutate(reply)
            return reply
        ssm.describe_parameters = malformed
        with pytest.raises(ValueError, match="published_namespace_unverified"):
            _run(fixture)
        assert fixture[2].write_dispatch_started is False


@pytest.mark.parametrize("field,value", [
    ("bootstrap_sha256", "0" * 64),
    ("source", "not-a-source-sha"),
    ("run_id", True),
    ("phase", "put_intent"),
    ("extra", "unexpected"),
])
def test_publication_receipt_shape_and_lineage_are_exact(field, value):
    fixture = _published()
    fixture[4][field] = value
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)
    assert fixture[2].write_dispatch_started is False


@pytest.mark.parametrize("bad_date", [
    datetime(2026, 10, 1),
    datetime.fromtimestamp(1, timezone.utc),
])
def test_parameter_creation_time_must_be_aware_and_inside_publication_window(bad_date):
    fixture = _published()
    fixture[5]["LastModifiedDate"] = bad_date
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)


def test_present_tenant_session_path_blocks_namespace_acceptance():
    fixture = _published()
    coordinator = fixture[0]
    ssm = coordinator.clients["ssm"]
    original = ssm.get_parameter
    tenant_path = f"/honda-mapit-mcp/dev/tenants/{coordinator.authority._tenant_keys[0]}/mapit-refresh-token"
    def present(**kwargs):
        if kwargs.get("Name") == tenant_path:
            return {"Parameter": {"Name": tenant_path},
                    "ResponseMetadata": {"HTTPStatusCode": 200}}
        return original(**kwargs)
    ssm.get_parameter = present
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)
    assert fixture[2].write_dispatch_started is False


def test_wrong_missing_parameter_error_shape_is_not_accepted_as_absence():
    fixture = _published()
    coordinator = fixture[0]
    ssm = coordinator.clients["ssm"]
    def wrong_error(**_kwargs):
        raise RuntimeError("provider detail must not escape")
    ssm.get_parameter = wrong_error
    with pytest.raises(ValueError, match="published_namespace_unverified"):
        _run(fixture)
    assert fixture[2].write_dispatch_started is False


def test_metadata_helper_remains_pre_enrollment_only_and_never_decrypts_config():
    fixture = _published()
    coordinator = fixture[0]
    ssm = coordinator.clients["ssm"]
    calls = []
    original_get = ssm.get_parameter
    original_describe = ssm.describe_parameters
    def get(**kwargs):
        calls.append(("get", kwargs))
        return original_get(**kwargs)
    def describe(**kwargs):
        calls.append(("describe", kwargs))
        return original_describe(**kwargs)
    ssm.get_parameter = get
    ssm.describe_parameters = describe
    assert _run(fixture)["sessions_absent"] is True
    assert all(not (kind == "get" and kwargs.get("Name") == CONFIG_PARAMETER)
               for kind, kwargs in calls)
    assert all(kind != "get" or kwargs.get("WithDecryption") is False
               for kind, kwargs in calls)
