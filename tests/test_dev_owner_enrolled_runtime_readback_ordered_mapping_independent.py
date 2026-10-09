from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

import pytest

import scripts.dev_owner_enrolled_runtime_readback as readback
from scripts.dev_owner_enrolled_runtime_readback import _json_document
from tests.test_dev_owner_enrolled_runtime_readback import (
    _build_owner_enrolled_current_state_fixture,
)


def _ordered(value):
    if isinstance(value, dict):
        return OrderedDict((key, _ordered(item)) for key, item in value.items())
    if isinstance(value, list):
        return [_ordered(item) for item in value]
    return value


def test_real_current_state_preflight_normalizes_nested_botocore_ordereddict(tmp_path, monkeypatch):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    current = fixture["current"]
    scenario = fixture["scenario"]
    expected = current.prior
    scenario.prior = _ordered(scenario.prior)

    # This fixture exercises the actual current-state verifier, its real
    # GetTemplate request/response path, resource inventory, and downstream
    # policy comparisons. Only the platform-specific ACL probe is stubbed.
    import scripts.dev_identity_binding_runtime_evidence as legacy_evidence
    monkeypatch.setattr(legacy_evidence, "validate_private_location", lambda path: Path(path))

    result = current("pre_update", fixture["delivery_binding"])

    assert result["phase"] == "pre_update"
    assert result["template_sha256"] == fixture["delivery"].auth["prior_template_sha256"]
    assert result["resource_count"] == 19
    assert current.prior == expected
    template_calls = [call for call in scenario.calls
                      if call[0:2] == ("cloudformation", "get_template")
                      and call[2].get("StackName") == current.authority["stack_id"]]
    assert len(template_calls) >= 1
    assert all(call[2]["TemplateStage"] == "Original" for call in template_calls)


@pytest.mark.parametrize("bad", [
    {"Resources": {"x": ("not-json",)}},
    {"Resources": {"x": float("nan")}},
    {"Resources": {"x": float("inf")}},
])
def test_sdk_mapping_normalizer_rejects_non_json_nested_values(bad):
    assert _json_document(_ordered(bad)) is None


def test_sdk_mapping_normalizer_rejects_pathological_depth_and_size():
    deep = {"leaf": None}
    for _ in range(66):
        deep = {"nested": deep}
    assert _json_document(deep) is None

    oversized = {"value": "x" * (64 * 1024)}
    assert _json_document(oversized) is None

    # Each scalar is within the per-field cap, but the whole document exceeds
    # the intended bound. This exercises the aggregate rejection path too.
    many_fields = {f"field-{index}": "y" * 10_000 for index in range(8)}
    assert _json_document(_ordered(many_fields)) is None


def test_oversized_mapping_is_rejected_before_final_canonicalization(monkeypatch):
    calls = []
    real_canonical = readback._canonical

    def observe(value):
        calls.append(value)
        return real_canonical(value)

    monkeypatch.setattr(readback, "_canonical", observe)
    value = _ordered({f"large-{index}": "z" * 20_000 for index in range(4)})

    assert _json_document(value) is None
    assert calls == []


def test_oversized_mapping_key_and_integer_are_rejected_safely():
    assert _json_document(_ordered({"k" * (64 * 1024 + 1): "value"})) is None
    assert _json_document({"value": 1 << 300_000}) is None
