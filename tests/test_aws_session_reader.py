import json

import pytest

from mapit.aws_session_reader import AwsSessionReader, AwsSessionReaderError


ACCOUNT = "123456789012"
PATH = "/honda-mapit-mcp/prod/mapit-refresh-token"
TOKEN = "synthetic-refresh-token-canary"
VERSION = 7
ARN = f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{PATH}"
META = {"ResponseMetadata": {"HTTPStatusCode": 200}}
_UNSET = object()


class FakeClient:
    def __init__(self, response=_UNSET, *, error=None, clock_change=None):
        self.response = _response() if response is _UNSET else response
        self.error = error
        self.clock_change = clock_change
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        if self.clock_change:
            self.clock_change()
        if self.error:
            raise self.error
        return self.response


class SequenceClock:
    def __init__(self, values):
        self.values = list(values)
        self.last = None

    def __call__(self):
        value = self.values.pop(0) if self.values else self.last
        self.last = value
        return value


def _response(**changes):
    parameter = {
        "Name": PATH,
        "ARN": ARN,
        "Type": "SecureString",
        "Value": TOKEN,
        "Version": VERSION,
        "DataType": "text",
    }
    parameter.update(changes)
    return {**META, "Parameter": parameter}


def _reader(client=None, *, version=VERSION, tier="Standard", account=ACCOUNT, monotonic=lambda: 10.0):
    return AwsSessionReader(
        client or FakeClient(), account_id=account, version=version, tier=tier, monotonic=monotonic
    )


def test_reads_one_exact_selected_version_and_hides_value_from_repr_and_safe_output():
    client = FakeClient()
    result = _reader(client).read_refresh_token(deadline=100.0)
    assert result.success is True
    assert result.refresh_token == TOKEN
    assert client.calls == [{"Name": f"{PATH}:{VERSION}", "WithDecryption": True}]
    assert TOKEN not in repr(result)
    assert TOKEN not in json.dumps(result.safe_projection())
    assert result.safe_projection() == {
        "success": True,
        "category": "session_read_verified",
        "parameter_version": VERSION,
        "tier_policy": "Standard",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"account": "bad"},
        {"account": "000000000000"},
        {"version": 0},
        {"version": True},
        {"version": 1.0},
        {"tier": "standard"},
        {"tier": ""},
    ],
)
def test_invalid_configuration_fails_before_any_client_call(kwargs):
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client, **kwargs)
    assert exc.value.category == "invalid_configuration"
    assert client.calls == []


@pytest.mark.parametrize("deadline", [None, True, float("nan"), float("inf"), 0, -1])
def test_invalid_deadline_fails_without_dispatch(deadline):
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client).read_refresh_token(deadline=deadline)
    assert exc.value.category == "deadline_invalid"
    assert client.calls == []


def test_expired_caller_deadline_fails_without_dispatch():
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client, monotonic=lambda: 12.0).read_refresh_token(deadline=12.0)
    assert exc.value.category == "deadline_expired"
    assert client.calls == []


def test_reader_caps_far_future_deadline_to_five_seconds():
    clock = SequenceClock([10.0, 10.0, 10.0, 15.0])
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client, monotonic=clock).read_refresh_token(deadline=1000.0)
    assert exc.value.category == "deadline_expired"
    assert len(client.calls) == 1


def test_large_integer_deadline_is_capped_without_float_overflow():
    result = _reader(FakeClient()).read_refresh_token(deadline=10**1000)
    assert result.success is True


def test_expiration_during_request_suppresses_token_return():
    clock = SequenceClock([10.0, 10.0, 10.0, 16.0])
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client, monotonic=clock).read_refresh_token(deadline=100.0)
    assert exc.value.category == "deadline_expired"
    assert len(client.calls) == 1


def test_clock_rollback_after_response_fails_closed():
    clock = SequenceClock([10.0, 10.0, 10.0, 10.0, 9.0])
    client = FakeClient()
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client, monotonic=clock).read_refresh_token(deadline=100.0)
    assert exc.value.category == "clock_rollback"
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "response,category",
    [
        (None, "response_invalid"),
        ({"ResponseMetadata": {"HTTPStatusCode": True}, "Parameter": {}}, "response_invalid"),
        ({"ResponseMetadata": {"HTTPStatusCode": 201}, "Parameter": {}}, "response_invalid"),
        ({**META, "Parameter": None}, "parameter_invalid"),
        (_response(Name=PATH + ":6"), "parameter_invalid"),
        (_response(ARN=ARN.replace(ACCOUNT, "999999999999")), "parameter_invalid"),
        (_response(Type="String"), "parameter_invalid"),
        (_response(Version=True), "parameter_invalid"),
        (_response(Version=VERSION + 1), "parameter_invalid"),
        (_response(DataType="binary"), "parameter_invalid"),
        (_response(Selector=":6"), "parameter_invalid"),
        (_response(SourceResult="provider-result"), "parameter_invalid"),
        (_response(SourceResult=""), "parameter_invalid"),
        (_response(SourceResult=None), "parameter_invalid"),
        (_response(Value=""), "value_invalid"),
        (_response(Value=None), "value_invalid"),
    ],
)
def test_invalid_provider_response_is_sanitized(response, category):
    client = FakeClient(response)
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client).read_refresh_token(deadline=100.0)
    assert exc.value.category == category
    assert TOKEN not in str(exc.value)


def test_exact_selector_is_optional_but_validated_when_present():
    assert _reader(FakeClient(_response(Selector=f":{VERSION}"))).read_refresh_token(deadline=100.0).success


@pytest.mark.parametrize("tier,limit", [("Standard", 4096), ("Advanced", 8192)])
def test_tier_specific_utf8_size_caps(tier, limit):
    accepted = _reader(FakeClient(_response(Value="x" * limit)), tier=tier).read_refresh_token(deadline=100.0)
    assert len(accepted.refresh_token) == limit
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(FakeClient(_response(Value="x" * (limit + 1))), tier=tier).read_refresh_token(deadline=100.0)
    assert exc.value.category == "value_too_large"


def test_utf8_bytes_not_character_count_define_tier_limit():
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(FakeClient(_response(Value="é" * 2049))).read_refresh_token(deadline=100.0)
    assert exc.value.category == "value_too_large"


def test_sdk_exception_text_and_chaining_never_escape():
    client = FakeClient(error=RuntimeError("secret-canary-provider-text"))
    with pytest.raises(AwsSessionReaderError) as exc:
        _reader(client).read_refresh_token(deadline=100.0)
    assert exc.value.category == "parameter_read_failed"
    assert "secret-canary" not in str(exc.value)
    assert exc.value.__cause__ is None
    assert len(client.calls) == 1


def test_pinned_sdk_get_parameter_request_shape_with_stubber():
    boto3 = pytest.importorskip("boto3")
    botocore_stub = pytest.importorskip("botocore.stub")
    client = boto3.client(
        "ssm",
        region_name="eu-west-1",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    stubber = botocore_stub.Stubber(client)
    stubber.add_response(
        "get_parameter",
        {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": {
            "Name": PATH,
            "ARN": ARN,
            "Type": "SecureString",
            "Value": TOKEN,
            "Version": VERSION,
            "Selector": f":{VERSION}",
            "DataType": "text",
        }},
        {"Name": f"{PATH}:{VERSION}", "WithDecryption": True},
    )
    with stubber:
        result = AwsSessionReader(
            client,
            account_id=ACCOUNT,
            version=VERSION,
            tier="Standard",
            monotonic=SequenceClock([10.0] * 5),
        ).read_refresh_token(deadline=100.0)
    assert result.refresh_token == TOKEN
