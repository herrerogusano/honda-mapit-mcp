from __future__ import annotations

from contextlib import contextmanager
import copy
import pytest

from scripts.aws_retained_dev_delivery_preflight import RetainedDevDeliveryPreflight, validate_botocore_models
from tests.test_cd_retained_dev_delivery_contract import _binding


class Journal:
    def __init__(self): self.state = None
    @contextmanager
    def locked(self): yield
    def load(self): return copy.deepcopy(self.state)
    def compare_and_set(self, expected_version, value):
        current = self.state.get("version") if isinstance(self.state, dict) else None
        if current != expected_version:
            return False
        candidate = copy.deepcopy(value)
        candidate["version"] = (expected_version or 0) + 1
        self.state = candidate
        return True


class Client:
    def __getattr__(self, name):
        def method(**kwargs):
            if name == "get_caller_identity": return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/operator", "ResponseMetadata": {"HTTPStatusCode": 200}}
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}
        return method


def test_pinned_botocore_models_cover_only_real_read_operations():
    pytest.importorskip("botocore.session")
    validate_botocore_models()


def test_constructor_requires_exact_client_set():
    try: RetainedDevDeliveryPreflight({}, Journal(), binding=_binding())
    except Exception as exc: assert getattr(exc, "category", None) == "clients_invalid"
    else: raise AssertionError("incomplete clients accepted")


def test_preflight_is_injected_and_read_only():
    pytest.importorskip("botocore.session")
    clients = {name: Client() for name in ("sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch")}
    result = RetainedDevDeliveryPreflight(clients, Journal(), binding=_binding(), wall_clock=lambda: 1900000001, monotonic=lambda: 1.0).run()
    assert result["ok"] is False
    assert result["category"] == "receipt_normative_mismatch"
