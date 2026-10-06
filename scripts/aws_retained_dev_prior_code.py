"""Injected, read-only capture of the initial retained-dev rollback ZIP.

No SDK, credential chain, downloader or file writer is constructed here.
The caller must supply the bounded direct-TLS downloader separately; this
offline core is not an operational acceptance receipt by itself.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import io
import math
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit
import zipfile

from scripts.aws_retained_dev_bootstrap import _canonical, _strict_mapping
from scripts.build_aws_retained_dev import HANDLER_CODE, build_retained_dev_template

MAX_ARCHIVE_BYTES = 1024 * 1024
REGION = "eu-west-1"
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"


class PriorCodeError(ValueError):
    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


@dataclass(frozen=True, repr=False)
class PriorCodeSnapshot:
    archive_bytes: bytes = field(repr=False)
    template_bytes: bytes = field(repr=False)
    zip_sha256: str = field(repr=False)
    template_sha256: str = field(repr=False)
    observed_epoch: int

    def __repr__(self) -> str:
        return "PriorCodeSnapshot(private=True)"


def capture_initial_prior_code(
    clients: Mapping[str, Any],
    downloader: Callable[[str, int, float], bytes],
    *,
    account_id: str,
    stack_arn: str,
    api_id: str,
    expected_caller_arn: str,
    authorized_from_epoch: int,
    authorized_until_epoch: int,
    wall_clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> PriorCodeSnapshot:
    """Capture only the exact initial inline503 scaffold, while proven closed."""
    if (
        not isinstance(clients, Mapping)
        or set(clients) != {"sts", "cloudformation", "lambda", "apigatewayv2"}
        or not callable(downloader)
        or type(account_id) is not str or not re.fullmatch(r"[0-9]{12}", account_id)
        or account_id == "000000000000"
        or type(stack_arn) is not str or not re.fullmatch(
            rf"arn:aws:cloudformation:{REGION}:{account_id}:stack/honda-mapit-mcp-dev-retained/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}", stack_arn)
        or type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id)
        or type(expected_caller_arn) is not str or not re.fullmatch(
            rf"arn:aws:(?:iam::{account_id}:(?:user|role)/[^\s:]+|sts::{account_id}:assumed-role/[^\s:/]+/[^\s:/]+)", expected_caller_arn)
        or type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
        or not 0 < authorized_from_epoch < authorized_until_epoch
        or authorized_until_epoch - authorized_from_epoch > 3600
    ):
        raise PriorCodeError("binding_invalid")
    started = monotonic()
    last_mono = started
    last_wall = 0.0

    def guard() -> tuple[int, float]:
        nonlocal last_mono, last_wall
        now_mono, now_wall = monotonic(), wall_clock()
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in (started, now_mono, now_wall)):
            raise PriorCodeError("clock_invalid")
        if started < 0 or now_mono < last_mono or now_wall < last_wall:
            raise PriorCodeError("clock_invalid")
        last_mono, last_wall = float(now_mono), float(now_wall)
        if not authorized_from_epoch <= now_wall < authorized_until_epoch or now_mono - started >= 30:
            raise PriorCodeError("window_expired")
        return int(now_wall), 30 - (now_mono - started)

    def call(service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        guard()
        try:
            value = getattr(clients[service], method)(**kwargs)
        except Exception:
            raise PriorCodeError("read_failed") from None
        guard()
        meta = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
        if not isinstance(meta, Mapping) or type(meta.get("HTTPStatusCode")) is not int or meta["HTTPStatusCode"] != 200:
            raise PriorCodeError("response_invalid")
        if any(key in value for key in ("NextToken", "NextMarker", "Marker")) or value.get("IsTruncated") not in (None, False):
            raise PriorCodeError("response_invalid")
        return value

    identity = call("sts", "get_caller_identity")
    if identity.get("Account") != account_id or identity.get("Arn") != expected_caller_arn:
        raise PriorCodeError("identity_mismatch")
    template = _strict_mapping(call("cloudformation", "get_template", StackName=stack_arn, TemplateStage="Original").get("TemplateBody"))
    expected_template = _canonical(build_retained_dev_template())
    if template is None or _canonical(template) != expected_template:
        raise PriorCodeError("initial_template_mismatch")
    function = call("lambda", "get_function", FunctionName=FUNCTION_NAME)
    config, code = function.get("Configuration"), function.get("Code")
    if not isinstance(config, Mapping) or not isinstance(code, Mapping):
        raise PriorCodeError("code_binding_mismatch")
    expected_config = {
        "FunctionName": FUNCTION_NAME,
        "FunctionArn": f"arn:aws:lambda:{REGION}:{account_id}:function:{FUNCTION_NAME}",
        "Runtime": "python3.13", "Handler": "index.handler", "Architectures": ["arm64"],
        "Role": f"arn:aws:iam::{account_id}:role/honda-mapit-mcp-dev-retained-handler-role",
        "MemorySize": 256, "Timeout": 20, "State": "Active", "LastUpdateStatus": "Successful",
    }
    if any(config.get(key) != value for key, value in expected_config.items()) or "Environment" in config:
        raise PriorCodeError("code_binding_mismatch")
    code_hash, code_size = config.get("CodeSha256"), config.get("CodeSize")
    if type(code_hash) is not str or type(code_size) is not int or not 0 < code_size <= MAX_ARCHIVE_BYTES:
        raise PriorCodeError("code_binding_mismatch")
    try:
        digest = base64.b64decode(code_hash, validate=True)
        if len(digest) != 32 or base64.b64encode(digest).decode("ascii") != code_hash:
            raise ValueError
    except Exception:
        raise PriorCodeError("code_binding_mismatch") from None
    if code.get("RepositoryType") != "S3" or type(code.get("Location")) is not str:
        raise PriorCodeError("download_location_invalid")
    location = code["Location"]
    try:
        parts = urlsplit(location)
        if (len(location) > 16384 or parts.scheme != "https" or parts.port not in (None, 443)
            or parts.username is not None or parts.password is not None or parts.fragment
            or not re.fullmatch(r"awslambda-eu-west-1-tasks\.s3\.eu-west-1\.amazonaws\.com", parts.hostname or "")
            or not parts.path.startswith("/") or not parts.query):
            raise ValueError
    except Exception:
        raise PriorCodeError("download_location_invalid") from None
    concurrency = call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
    if concurrency.get("ReservedConcurrentExecutions") != 0:
        raise PriorCodeError("not_closed")
    api = call("apigatewayv2", "get_api", ApiId=api_id)
    if any(api.get(key) != value for key, value in {
        "ApiId": api_id, "Name": "honda-mapit-mcp-dev-retained-api", "ProtocolType": "HTTP",
        "DisableExecuteApiEndpoint": True,
    }.items()) or api.get("DisableExecuteApiEndpoint") is not True:
        raise PriorCodeError("not_closed")
    if call("apigatewayv2", "get_routes", ApiId=api_id, MaxResults="100").get("Items") != []:
        raise PriorCodeError("not_closed")
    _, remaining = guard()
    try:
        body = downloader(location, MAX_ARCHIVE_BYTES, remaining)
    except Exception:
        raise PriorCodeError("download_failed") from None
    observed, _ = guard()
    if type(body) is not bytes or len(body) != code_size or hashlib.sha256(body).digest() != digest:
        raise PriorCodeError("archive_mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            if len(infos) != 1 or infos[0].filename != "index.py" or infos[0].file_size > 65536:
                raise ValueError
            info = infos[0]
            if info.flag_bits & 1 or (info.external_attr >> 16) & 0o170000 not in (0, 0o100000):
                raise ValueError
            if archive.read(info) != HANDLER_CODE.encode("utf-8"):
                raise ValueError
    except Exception:
        raise PriorCodeError("archive_mismatch") from None
    return PriorCodeSnapshot(body, expected_template, digest.hex(), hashlib.sha256(expected_template).hexdigest(), observed)
