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


def test_s3_lifecycle_method_uses_the_real_boto3_operation_name():
    pytest.importorskip("botocore.session")
    from botocore.session import get_session

    session = get_session()
    client = session.create_client("s3", region_name="eu-west-1", aws_access_key_id="AKIA" + "0" * 16, aws_secret_access_key="0" * 40, aws_session_token="0" * 32)
    try:
        assert client.meta.method_to_api_mapping["get_bucket_lifecycle_configuration"] == "GetBucketLifecycleConfiguration"
    finally:
        client.close()


def test_every_preflight_method_matches_the_real_sdk_client(monkeypatch):
    pytest.importorskip("botocore.session")
    import socket
    from botocore.session import get_session
    from scripts.aws_retained_dev_delivery_preflight import _SDK_MODEL_SPECS

    def deny_network(*args, **kwargs):
        raise AssertionError("SDK model test attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    session = get_session()
    checked = 0
    for name, operations in _SDK_MODEL_SPECS.items():
        client = session.create_client(
            {"sfn": "stepfunctions"}.get(name, name), region_name="eu-west-1",
            aws_access_key_id="synthetic", aws_secret_access_key="synthetic",
        )
        try:
            for method, (operation, _, _) in operations.items():
                assert client.meta.method_to_api_mapping[method] == operation
                checked += 1
        finally:
            client.close()
    assert checked == 34


def test_runtime_model_validation_never_constructs_a_client(monkeypatch):
    pytest.importorskip("botocore.session")
    from botocore.session import Session

    def deny_client(*args, **kwargs):
        raise AssertionError("injected preflight constructed an SDK client")

    monkeypatch.setattr(Session, "create_client", deny_client)
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
