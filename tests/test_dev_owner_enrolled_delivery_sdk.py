from __future__ import annotations

import copy
import hashlib
import json
from types import MappingProxyType, SimpleNamespace

import pytest

from scripts.dev_owner_enrolled_delivery_sdk import (
    DeliveryClientBundle,
    OwnerEnrolledDeliverySdk,
    OwnerEnrolledDeliverySdkError,
    _CLIENT_ENDPOINTS,
    build_explicit_delivery_clients,
)
from test_dev_owner_enrolled_delivery import Harness


class FakeClient:
    def __init__(self, service, region, endpoint, *, config=None, calls=None):
        self.meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name=service), region_name=region,
            endpoint_url=endpoint, config=config or SimpleNamespace(
                retries={"mode": "standard", "total_max_attempts": 1},
                signature_version="v4", proxies={}, connect_timeout=2, read_timeout=3),
        )
        self._endpoint = SimpleNamespace(http_session=SimpleNamespace(_verify=True))
        self.calls = calls if calls is not None else []
        self.identity = {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": "123456789012",
                         "Arn": "arn:aws:iam::123456789012:user/dev-operator"}
        self.api = {"ResponseMetadata": {"HTTPStatusCode": 200}, "ApiId": "abcdefghij",
                    "DisableExecuteApiEndpoint": True}
        self.concurrency = {"ResponseMetadata": {"HTTPStatusCode": 200},
                            "ReservedConcurrentExecutions": 0}
        self.put_response = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        self.head = {}
        self.update_response = {"ResponseMetadata": {"HTTPStatusCode": 200},
                                "StackId": ""}
        self.raise_on = set()

    def _invoke(self, method, **kwargs):
        self.calls.append((method, copy.deepcopy(kwargs)))
        if method in self.raise_on:
            raise RuntimeError("sensitive fake error")
        return getattr(self, method + "_response", None)

    def get_caller_identity(self, **kwargs):
        self.calls.append(("get_caller_identity", kwargs))
        if "get_caller_identity" in self.raise_on:
            raise RuntimeError("sensitive fake error")
        return self.identity

    def get_api(self, **kwargs):
        self.calls.append(("get_api", kwargs))
        return self.api

    def get_function_concurrency(self, **kwargs):
        self.calls.append(("get_function_concurrency", kwargs))
        return self.concurrency

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        if "put_object" in self.raise_on:
            raise RuntimeError("sensitive fake error")
        return self.put_response

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        if "head_object" in self.raise_on:
            raise RuntimeError("sensitive fake error")
        return self.head

    def update_stack(self, **kwargs):
        self.calls.append(("update_stack", kwargs))
        if "update_stack" in self.raise_on:
            raise RuntimeError("sensitive fake error")
        return {**self.update_response, "StackId": kwargs["StackName"]}


def _bundle_for(raw_clients):
    frozen = SimpleNamespace(access_key="AKIAEXAMPLE123456", secret_key="do-not-print-secret-value", token=None)

    class Provider:
        def get_frozen_credentials(self):
            return frozen

    class Session:
        def get_credentials(self):
            return Provider()

        def client(self, service, **kwargs):
            name = next(key for key, item in _CLIENT_ENDPOINTS.items() if item[0] == service)
            client = raw_clients[name]
            client.meta = SimpleNamespace(service_model=SimpleNamespace(service_name=service),
                region_name=kwargs["region_name"], endpoint_url=kwargs["endpoint_url"], config=kwargs["config"])
            client._endpoint.http_session._verify = kwargs["verify"]
            return client

    return build_explicit_delivery_clients(session_factory=lambda **_kwargs: Session(), environ={"PATH": "safe"})


def _setup():
    h = Harness()
    raw_clients = {
        name: FakeClient(service, region, endpoint)
        for name, (service, region, endpoint) in _CLIENT_ENDPOINTS.items()
    }
    bundle = _bundle_for(raw_clients)
    clients = bundle.clients
    target = h.coordinator.target
    target_sha = hashlib.sha256(
        json.dumps(target, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False).encode("ascii")
    ).hexdigest()
    clients["apigatewayv2"].api["ApiId"] = h.auth["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
    adapter = OwnerEnrolledDeliverySdk(
        client_bundle=bundle, authority=h.auth,
        target_template_sha256=target_sha, clock=h.clock, monotonic=h.monotonic_clock,
    )
    return h, clients, adapter, target, target_sha


def test_publish_once_uses_conditional_private_s3_write_and_exact_head_receipt():
    h, clients, adapter, _target, _target_sha = _setup()
    archive = b"bounded synthetic archive"
    digest = hashlib.sha256(archive).hexdigest()
    import base64
    checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
    clients["s3"].head = {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "ContentLength": len(archive),
        "ChecksumSHA256": checksum, "ServerSideEncryption": "AES256",
        "ContentType": "application/zip",
    }
    receipt = adapter.publish_once({"authority": h.auth}, archive)
    assert receipt["status"] == "verified"
    assert receipt["bucket"] == h.auth["artifact_bucket"]
    assert receipt["key"] == f"runtime/{digest}.zip"
    assert receipt["sha256"] == digest
    put = [kwargs for method, kwargs in clients["s3"].calls if method == "put_object"]
    head = [kwargs for method, kwargs in clients["s3"].calls if method == "head_object"]
    assert len(put) == len(head) == 1
    assert put[0]["IfNoneMatch"] == "*"
    assert put[0]["ExpectedBucketOwner"] == h.auth["account_id"]
    assert put[0]["ServerSideEncryption"] == "AES256"
    assert put[0]["ChecksumSHA256"] == checksum
    assert head[0]["ExpectedBucketOwner"] == h.auth["account_id"]


def test_update_once_is_pinned_to_exact_target_and_stack_role_token():
    h, clients, adapter, target, target_sha = _setup()
    token = f"owner-enrolled-{h.auth['run_id']}"
    result = adapter.update_once(h.auth["stack_id"], target, token, h.auth["service_role_arn"])
    assert result == {"status": "acknowledged", "http_status": 200,
                      "stack_id": h.auth["stack_id"], "client_request_token": token,
                      "target_template_sha256": target_sha}
    call = [kwargs for method, kwargs in clients["cloudformation"].calls if method == "update_stack"]
    assert len(call) == 1
    assert call[0]["StackName"] == h.auth["stack_id"]
    assert call[0]["RoleARN"] == h.auth["service_role_arn"]
    assert call[0]["ClientRequestToken"] == token
    assert call[0]["Capabilities"] == ["CAPABILITY_NAMED_IAM"]


def test_wrong_target_fails_before_any_external_call():
    h, clients, adapter, target, _sha = _setup()
    changed = copy.deepcopy(target)
    changed["Description"] = "not the accepted target"
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
        adapter.update_once(h.auth["stack_id"], changed,
                            f"owner-enrolled-{h.auth['run_id']}", h.auth["service_role_arn"])
    assert all(not client.calls for client in clients.values())


@pytest.mark.parametrize("field,value", [
    ("identity", {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": "000000000000",
                   "Arn": "arn:aws:iam::000000000000:user/other"}),
    ("api", {"ResponseMetadata": {"HTTPStatusCode": 200}, "ApiId": "abcdefghij",
             "DisableExecuteApiEndpoint": False}),
    ("concurrency", {"ResponseMetadata": {"HTTPStatusCode": 200},
                     "ReservedConcurrentExecutions": 1}),
])
def test_identity_or_closed_state_mismatch_stops_before_write(field, value):
    h, clients, adapter, target, _sha = _setup()
    client = clients["sts"] if field == "identity" else clients["apigatewayv2"] if field == "api" else clients["lambda"]
    setattr(client, field, value)
    with pytest.raises(OwnerEnrolledDeliverySdkError):
        adapter.update_once(adapter.authority["stack_id"], target,
                            f"owner-enrolled-{adapter.authority['run_id']}",
                            adapter.authority["service_role_arn"])
    assert not [call for call in clients["cloudformation"].calls if call[0] == "update_stack"]


def test_ambiguous_put_and_update_are_sticky_and_never_retried():
    h, clients, adapter, target, _sha = _setup()
    clients["s3"].raise_on.add("put_object")
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, b"archive")
    clients["s3"].raise_on.clear()
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, b"archive")
    assert len([x for x in clients["s3"].calls if x[0] == "put_object"]) == 1

    h2, clients2, adapter2, target2, _sha2 = _setup()
    clients2["cloudformation"].raise_on.add("update_stack")
    args = (h2.auth["stack_id"], target2, f"owner-enrolled-{h2.auth['run_id']}",
            h2.auth["service_role_arn"])
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="update_write_unknown"):
        adapter2.update_once(*args)
    clients2["cloudformation"].raise_on.clear()
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="update_write_unknown"):
        adapter2.update_once(*args)
    assert len([x for x in clients2["cloudformation"].calls if x[0] == "update_stack"]) == 1


def test_explicit_client_factory_freezes_credentials_once_for_every_client():
    pytest.importorskip("boto3")
    calls = []
    frozen = SimpleNamespace(access_key="AKIAEXAMPLE123456", secret_key="secret-value-long-enough",
                             token="session-value-long-enough")
    class Provider:
        def get_frozen_credentials(self):
            calls.append(("freeze",))
            return frozen
    class Session:
        def __init__(self, **kwargs):
            calls.append(("session", kwargs))
        def get_credentials(self):
            calls.append(("get_credentials",))
            return Provider()
        def client(self, service, **kwargs):
            calls.append(("client", service, kwargs))
            region = kwargs["region_name"]
            endpoint = kwargs["endpoint_url"]
            return FakeClient(service, region, endpoint, config=kwargs["config"])
    bundle = build_explicit_delivery_clients(
        session_factory=Session, environ={"PATH": "safe"})
    clients, snapshot = bundle.clients, bundle.credential_snapshot
    assert set(clients) == set(_CLIENT_ENDPOINTS)
    assert sum(call[0] == "freeze" for call in calls) == 1
    client_calls = [call for call in calls if call[0] == "client"]
    assert len(client_calls) == len(_CLIENT_ENDPOINTS)
    assert all(call[2]["aws_access_key_id"] == frozen.access_key
               and call[2]["aws_secret_access_key"] == frozen.secret_key
               and call[2]["aws_session_token"] == frozen.token for call in client_calls)
    assert repr(snapshot) == "CredentialSnapshot(<redacted>)"
    assert "secret-value" not in repr(snapshot) and "session-value" not in repr(snapshot)
    assert repr(bundle) == "DeliveryClientBundle(<redacted>)"
    with pytest.raises(TypeError):
        bundle.clients["s3"] = object()


def test_ambient_credential_configuration_rejected_before_session_creation():
    created = []
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="client_setup_failed"):
        build_explicit_delivery_clients(session_factory=lambda **_kw: created.append(True),
                                       environ={"AWS_PROFILE": "bad"})
    assert created == []


def test_bad_s3_readback_is_not_accepted_and_write_remains_consumed():
    h, clients, adapter, _target, _sha = _setup()
    clients["s3"].head = {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "ContentLength": 1,
        "ChecksumSHA256": "wrong", "ServerSideEncryption": "AES256",
        "ContentType": "application/zip",
    }
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_readback_unverified"):
        adapter.publish_once({"authority": h.auth}, b"archive")
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, b"archive")
    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1


def test_bad_stack_or_token_is_rejected_without_external_calls():
    h, clients, adapter, target, _sha = _setup()
    for stack_id, token, role in (
        ("wrong-stack", f"owner-enrolled-{h.auth['run_id']}", h.auth["service_role_arn"]),
        (h.auth["stack_id"], "wrong-token", h.auth["service_role_arn"]),
        (h.auth["stack_id"], f"owner-enrolled-{h.auth['run_id']}", "arn:aws:iam::123456789012:role/other"),
    ):
        with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
            adapter.update_once(stack_id, target, token, role)
    assert not [call for call in clients["cloudformation"].calls if call[0] == "update_stack"]


def test_clock_failure_permanently_invalidates_adapter_before_write():
    h, clients, adapter, target, _target_sha = _setup()
    wall = [h.auth["authorized_from_epoch"] + 10]
    mono = [10.0]
    adapter.clock = lambda: wall[0]
    adapter.monotonic = lambda: mono[0]
    adapter._last_wall = wall[0]
    adapter._started_mono = adapter._last_mono = mono[0]
    wall[0] -= 1
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="window_closed"):
        adapter.update_once(h.auth["stack_id"], target, f"owner-enrolled-{h.auth['run_id']}",
                            h.auth["service_role_arn"])
    wall[0] += 10
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="window_closed"):
        adapter.update_once(h.auth["stack_id"], target, f"owner-enrolled-{h.auth['run_id']}",
                            h.auth["service_role_arn"])
    assert all(not client.calls for client in clients.values())


def test_forged_clone_and_changed_client_identity_are_unregistered():
    h, clients, adapter, _target, _target_sha = _setup()
    forged = DeliveryClientBundle(dict(clients), adapter.credential_snapshot)
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
        OwnerEnrolledDeliverySdk(client_bundle=forged, authority=h.auth,
            target_template_sha256=adapter.target_template_sha256, clock=h.clock,
            monotonic=h.monotonic_clock)

    swapped = dict(clients)
    swapped["s3"] = FakeClient(*_CLIENT_ENDPOINTS["s3"])
    object.__setattr__(adapter.client_bundle, "_clients", MappingProxyType(swapped))
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
        OwnerEnrolledDeliverySdk(client_bundle=adapter.client_bundle, authority=h.auth,
            target_template_sha256=adapter.target_template_sha256, clock=h.clock,
            monotonic=h.monotonic_clock)
