import base64
from copy import deepcopy
import hashlib
import io
from types import SimpleNamespace
import zipfile

import pytest

from scripts.aws_retained_dev_prior_code import capture_initial_prior_code, PriorCodeError
from scripts.build_aws_retained_dev import HANDLER_CODE, build_retained_dev_template

ACCOUNT = "123456789012"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-1111-4111-8111-111111111111"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/synthetic"


def ok(**values):
    return dict(ResponseMetadata={"HTTPStatusCode": 200}, **values)


def fixture():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("index.py", HANDLER_CODE)
    body = stream.getvalue()
    config = dict(FunctionName="honda-mapit-mcp-dev-retained-handler",
        FunctionArn=f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler",
        Runtime="python3.13", Handler="index.handler", Architectures=["arm64"],
        Role=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        MemorySize=256, Timeout=20, State="Active", LastUpdateStatus="Successful",
        CodeSha256=base64.b64encode(hashlib.sha256(body).digest()).decode(), CodeSize=len(body))
    template = build_retained_dev_template()
    code = dict(RepositoryType="S3", Location="https://awslambda-eu-west-1-tasks.s3.eu-west-1.amazonaws.com/snapshots/synthetic?X-Amz-Signature=synthetic")
    clients = {
        "sts": SimpleNamespace(get_caller_identity=lambda **kw: ok(Account=ACCOUNT, Arn=CALLER)),
        "cloudformation": SimpleNamespace(get_template=lambda **kw: ok(TemplateBody=deepcopy(template))),
        "lambda": SimpleNamespace(get_function=lambda **kw: ok(Configuration=deepcopy(config), Code=deepcopy(code)), get_function_concurrency=lambda **kw: ok(ReservedConcurrentExecutions=0)),
        "apigatewayv2": SimpleNamespace(get_api=lambda **kw: ok(ApiId="abcdefghij", Name="honda-mapit-mcp-dev-retained-api", ProtocolType="HTTP", DisableExecuteApiEndpoint=True), get_routes=lambda **kw: ok(Items=[])),
    }
    return clients, body, template, code


def capture(clients, body, **changes):
    kwargs = dict(account_id=ACCOUNT, stack_arn=STACK, api_id="abcdefghij", expected_caller_arn=CALLER,
        authorized_from_epoch=90, authorized_until_epoch=200,
        wall_clock=lambda: 100, monotonic=lambda: 1)
    kwargs.update(changes)
    return capture_initial_prior_code(clients, lambda *args: body, **kwargs)


def test_exact_initial_capture_is_private_and_byte_exact():
    clients, body, _, _ = fixture()
    snapshot = capture(clients, body)
    assert snapshot.archive_bytes == body
    assert snapshot.zip_sha256 == hashlib.sha256(body).hexdigest()
    assert repr(snapshot) == "PriorCodeSnapshot(private=True)"


def test_payload_checksum_mismatch_rejected():
    clients, body, _, _ = fixture()
    with pytest.raises(PriorCodeError, match="archive_mismatch"):
        capture(clients, body + b"unexpected")


def test_mutated_initial_template_rejected_before_download():
    clients, body, template, _ = fixture()
    template["Resources"]["McpHandler"]["Properties"]["Environment"] = {"Variables": {"UNEXPECTED": "1"}}
    with pytest.raises(PriorCodeError, match="initial_template_mismatch"):
        capture(clients, body)


@pytest.mark.parametrize("location", ["http://awslambda-eu-west-1-tasks.s3.eu-west-1.amazonaws.com/x?q=1", "https://evil.invalid/x?q=1", "https://awslambda-eu-west-1-tasks.s3.eu-west-1.amazonaws.com:444/x?q=1"])
def test_untrusted_download_location_rejected(location):
    clients, body, _, code = fixture()
    code["Location"] = location
    with pytest.raises(PriorCodeError, match="download_location_invalid"):
        capture(clients, body)


def test_monotonic_regression_rejected():
    clients, body, _, _ = fixture()
    values = iter([1, 2, 1])
    with pytest.raises(PriorCodeError, match="clock_invalid"):
        capture(clients, body, monotonic=lambda: next(values))


def test_not_closed_rejected():
    clients, body, _, _ = fixture()
    clients["lambda"].get_function_concurrency = lambda **kw: ok(ReservedConcurrentExecutions=1)
    with pytest.raises(PriorCodeError, match="not_closed"):
        capture(clients, body)
