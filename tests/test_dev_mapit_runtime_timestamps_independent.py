from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

import scripts.dev_mapit_runtime_evidence as evidence
from tests.test_dev_mapit_runtime_evidence_independent import _rows, _wrapper_inputs


class _ResourceReader:
    def __init__(self, template, rows):
        self.template = template
        self.rows = rows
        self.resource_reads = 0
        self.calls = []

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        return {"TemplateBody": self.template, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_stack_resources(self, **kwargs):
        self.calls.append(("list_stack_resources", kwargs))
        self.resource_reads += 1
        rows = self.rows(self.resource_reads) if callable(self.rows) else self.rows
        return {"StackResourceSummaries": copy.deepcopy(rows),
                "ResponseMetadata": {"HTTPStatusCode": 200}}


def _invoke(tmp_path, monkeypatch, rows):
    authority, bundle, mapit_template, app, clients, bundle_path, old_policy = _wrapper_inputs(tmp_path)
    instant = datetime(2026, 10, 9, 12, 34, 56, 123456, tzinfo=timezone.utc)
    dated_rows = _rows(app)
    for row in dated_rows:
        row["LastUpdatedTimestamp"] = instant
    clients["cloudformation"] = _ResourceReader(app, rows(dated_rows) if callable(rows) else dated_rows)
    # Exercise the actual verifier composition/current-template reader while
    # keeping unrelated historical and legacy validation at their injected
    # seams. No cloud call is involved.
    monkeypatch.setattr(evidence, "_validate_historical_bootstrap", lambda **_kwargs: old_policy)
    monkeypatch.setattr(evidence, "verify_accepted_runtime", lambda *_args, **_kwargs: {"verified": True})
    callback = evidence.make_mapit_runtime_evidence_verifier(
        bundle_path,
        synthetic_binding_path=bundle_path,
        synthetic_authorization_path=bundle_path,
        synthetic_state_dir=tmp_path,
        acl_checker=lambda _path: True,
        monotonic=lambda: 10.0,
    )
    return callback(clients, authority, mapit_template, phase="readback"), clients


def test_full_callback_accepts_native_aware_sdk_timestamps(tmp_path, monkeypatch):
    result, clients = _invoke(tmp_path, monkeypatch, lambda rows: rows)
    assert result["verified"] is True
    assert result["api_closed"] is True and result["reserve_zero"] is True
    assert clients["cloudformation"].resource_reads == 2


@pytest.mark.parametrize("drift", ["timestamp", "physical_id", "status", "extra_field"])
def test_full_callback_rejects_any_resource_summary_drift_between_reads(tmp_path, monkeypatch, drift):
    def rows_for_read(base_rows):
        def select(read_number):
            rows = copy.deepcopy(base_rows)
            if read_number == 2:
                victim = rows[0]
                if drift == "timestamp":
                    victim["LastUpdatedTimestamp"] += timedelta(seconds=1)
                elif drift == "physical_id":
                    victim["PhysicalResourceId"] += "-drift"
                elif drift == "status":
                    victim["ResourceStatus"] = "UPDATE_COMPLETE"
                else:
                    victim["UnexpectedField"] = "drift"
            return rows
        return select

    result, clients = _invoke(tmp_path, monkeypatch, rows_for_read)
    assert result["verified"] is False
    assert clients["cloudformation"].resource_reads == 2
    # A drifted closure must stop before the final independent API/Lambda reads.
    assert clients["apigatewayv2"].calls == []
    assert clients["lambda"].calls == []
