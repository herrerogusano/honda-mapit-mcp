from __future__ import annotations

import json

import pytest

from scripts import probe_aws_dev_enrolled_arm as probe


def test_output_rejects_duplicate_checks_envelope_keys():
    """A duplicate JSON key must not let an ambiguous child result pass."""
    valid_checks = json.dumps(dict.fromkeys(probe.CHECKS, True), separators=(",", ":"))
    payload = '{"checks":' + valid_checks + ',"checks":' + valid_checks + '}'
    with pytest.raises(probe.multi.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_output(payload)


def test_output_rejects_duplicate_check_names():
    entries = [f'{json.dumps(name)}:{"false" if name == probe.CHECKS[0] else "true"}'
               for name in probe.CHECKS]
    entries.insert(1, f'{json.dumps(probe.CHECKS[0])}:true')
    payload = '{"checks":{' + ",".join(entries) + "}}"
    with pytest.raises(probe.multi.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_output(payload)


def test_arm_probe_does_not_claim_mapit_session_or_external_business_reads():
    assert "missing_session_denied" in probe.CHECKS
    assert "revocation_denied" in probe.CHECKS
    assert "expired_window_denied" in probe.CHECKS
    assert "mapit_session_succeeded" not in probe.CHECKS
    assert "external_business_read_succeeded" not in probe.CHECKS
    assert 'raise ValueError("synthetic_session_absent")' in probe._CONTAINER_PROBE
