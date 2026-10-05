"""Independent pinned-SDK shape check; Stubber performs no network calls."""

import pytest

from mapit.aws_session_publication import publish_standard_session


def test_create_only_put_and_pinned_get_match_installed_ssm_model():
    boto3 = pytest.importorskip("boto3")
    stubber_module = pytest.importorskip("botocore.stub")

    account = "123456789012"
    path = "/honda-mapit-mcp/prod/mapit-refresh-token"
    token = "synthetic-publication-canary"
    version = 1
    client = boto3.client(
        "ssm",
        region_name="eu-west-1",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    stubber = stubber_module.Stubber(client)
    stubber.add_response(
        "put_parameter",
        {"Version": version, "Tier": "Standard", "ResponseMetadata": {"HTTPStatusCode": 200}},
        {
            "Name": path,
            "Value": token,
            "Type": "SecureString",
            "KeyId": "alias/aws/ssm",
            "Overwrite": False,
            "Tier": "Standard",
            "DataType": "text",
            "Tags": [
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "prod"},
                {"Key": "Purpose", "Value": "owner-session"},
            ],
        },
    )
    stubber.add_response(
        "get_parameter",
        {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Parameter": {
                "Name": path,
                "ARN": f"arn:aws:ssm:eu-west-1:{account}:parameter{path}",
                "Type": "SecureString",
                "Value": token,
                "Version": version,
                "DataType": "text",
            }
        },
        {"Name": f"{path}:{version}", "WithDecryption": True},
    )

    with stubber:
        result = publish_standard_session(
            client,
            token,
            account_id=account,
            deadline=20.0,
            monotonic=lambda: 10.0,
        )

    assert result.success is True
    assert result.write_acknowledged is True
    assert result.parameter_version == version
