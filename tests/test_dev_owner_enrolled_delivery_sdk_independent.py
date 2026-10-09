from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.dev_owner_enrolled_delivery_sdk import (
    DeliveryClientBundle,
    OwnerEnrolledDeliverySdk,
    OwnerEnrolledDeliverySdkError,
)
from scripts.dev_owner_enrolled_login_lineage import credential_snapshot_from_explicit_credentials
from test_dev_owner_enrolled_delivery_sdk import FakeClient, _CLIENT_ENDPOINTS, _setup


def test_bundle_rejects_structurally_valid_clients_paired_with_foreign_snapshot():
    """A bundle must be factory-associated, not merely structurally well formed."""
    clients = {
        name: FakeClient(service, region, endpoint)
        for name, (service, region, endpoint) in _CLIENT_ENDPOINTS.items()
    }
    snapshot = credential_snapshot_from_explicit_credentials(SimpleNamespace(
        access_key="AKIAFOREIGN123456", secret_key="foreign-secret-value-long", token=None))

    # Construction is intentionally non-authoritative; only the explicit
    # factory registers a bundle accepted by the delivery adapter.
    forged = DeliveryClientBundle(clients, snapshot)
    h, _trusted_clients, trusted_adapter, _target, _sha = _setup()
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
        OwnerEnrolledDeliverySdk(
            client_bundle=forged,
            authority=h.auth,
            target_template_sha256=trusted_adapter.target_template_sha256,
            clock=h.clock,
            monotonic=h.monotonic_clock,
        )
    assert all(not client.calls for client in clients.values())


def test_non_200_put_ack_consumes_attempt_and_never_dispatches_again():
    _h, clients, adapter, _target, _target_sha = _setup()
    clients["s3"].put_response = {"ResponseMetadata": {"HTTPStatusCode": 500}}

    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": adapter.authority}, b"bounded archive")
    clients["s3"].put_response = {"ResponseMetadata": {"HTTPStatusCode": 200}}
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": adapter.authority}, b"bounded archive")

    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1


def test_post_update_identity_drift_is_reported_and_update_is_not_replayed():
    h, clients, adapter, target, _target_sha = _setup()
    identity_calls = 0
    original = clients["sts"].get_caller_identity

    def drift_after_write(**kwargs):
        nonlocal identity_calls
        identity_calls += 1
        if identity_calls >= 2:
            return {"ResponseMetadata": {"HTTPStatusCode": 200},
                    "Account": "000000000000", "Arn": "arn:aws:iam::000000000000:user/other"}
        return original(**kwargs)

    clients["sts"].get_caller_identity = drift_after_write
    args = (h.auth["stack_id"], target, f"owner-enrolled-{h.auth['run_id']}",
            h.auth["service_role_arn"])
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="identity_unverified"):
        adapter.update_once(*args)
    with pytest.raises(OwnerEnrolledDeliverySdkError):
        adapter.update_once(*args)
    assert len([call for call in clients["cloudformation"].calls
                if call[0] == "update_stack"]) == 1


def test_real_botocore_clients_accept_one_exact_stubbed_s3_publication():
    boto3 = pytest.importorskip("boto3")
    Stubber = pytest.importorskip("botocore.stub").Stubber
    import base64
    import hashlib

    from scripts.dev_owner_enrolled_delivery_sdk import (
        OwnerEnrolledDeliverySdk,
        build_explicit_delivery_clients,
    )

    h, _fake_clients, _fake_adapter, _target, target_sha = _setup()
    session_factory = lambda *, region_name: boto3.Session(
        aws_access_key_id="AKIA1234567890ABCDE",
        aws_secret_access_key="synthetic-secret-value-long-enough",
        aws_session_token="synthetic-session-token-long-enough",
        region_name=region_name,
    )
    bundle = build_explicit_delivery_clients(
        session_factory=session_factory,
        environ={"PATH": "safe"},
    )
    clients = bundle.clients
    api_id = h.auth["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
    body = b"stubbed local archive"
    digest = hashlib.sha256(body).hexdigest()
    checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
    put_params = {
        "Bucket": h.auth["artifact_bucket"],
        "Key": f"runtime/{digest}.zip",
        "Body": body,
        "IfNoneMatch": "*",
        "ExpectedBucketOwner": h.auth["account_id"],
        "ServerSideEncryption": "AES256",
        "ChecksumSHA256": checksum,
        "ContentType": "application/zip",
    }
    head_params = {"Bucket": h.auth["artifact_bucket"], "Key": f"runtime/{digest}.zip",
                   "ChecksumMode": "ENABLED", "ExpectedBucketOwner": h.auth["account_id"]}
    identity = {"Account": h.auth["account_id"], "Arn": h.auth["operator_arn"], "UserId": "AIDATEST",
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    identity_result = {"get_caller_identity": [identity, {}]}
    api_result = {"get_api": [{"ApiId": api_id, "Name": "synthetic", "ProtocolType": "HTTP",
                                "DisableExecuteApiEndpoint": True,
                                "ResponseMetadata": {"HTTPStatusCode": 200}}, {"ApiId": api_id}]}
    lambda_result = {"get_function_concurrency": [{"ReservedConcurrentExecutions": 0,
                                                    "ResponseMetadata": {"HTTPStatusCode": 200}},
                                                   {"FunctionName": "honda-mapit-mcp-dev-retained-handler"}]}
    head_result = {"ContentLength": len(body), "ChecksumSHA256": checksum,
                   "ServerSideEncryption": "AES256", "ContentType": "application/zip",
                   "ResponseMetadata": {"HTTPStatusCode": 200}}
    adapter = OwnerEnrolledDeliverySdk(
        client_bundle=bundle,
        authority=h.auth,
        target_template_sha256=target_sha,
        clock=h.clock,
        monotonic=h.monotonic_clock,
    )
    with (Stubber(clients["sts"]) as sts_stub,
          Stubber(clients["apigatewayv2"]) as api_stub,
          Stubber(clients["lambda"]) as lambda_stub,
          Stubber(clients["s3"]) as s3_stub):
        for _ in range(2):
            sts_stub.add_response("get_caller_identity", identity_result["get_caller_identity"][0],
                                  identity_result["get_caller_identity"][1])
            api_stub.add_response("get_api", api_result["get_api"][0], api_result["get_api"][1])
            lambda_stub.add_response("get_function_concurrency", lambda_result["get_function_concurrency"][0],
                                     lambda_result["get_function_concurrency"][1])
        s3_stub.add_response("put_object", {"ResponseMetadata": {"HTTPStatusCode": 200}}, put_params)
        s3_stub.add_response("head_object", head_result, head_params)
        receipt = adapter.publish_once({"authority": h.auth}, body)
        assert receipt["status"] == "verified"
        assert receipt["sha256"] == digest
        sts_stub.assert_no_pending_responses()
        api_stub.assert_no_pending_responses()
        lambda_stub.assert_no_pending_responses()
        s3_stub.assert_no_pending_responses()
