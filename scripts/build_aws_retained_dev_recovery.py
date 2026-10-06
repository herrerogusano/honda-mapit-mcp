"""Pure factory for the retained-dev initial-code recovery artifact.

This is deliberately separate from the normal runtime builder.  It accepts
only the typed snapshot produced by ``capture_initial_prior_code`` and emits a
closed recovery template whose Lambda code is an immutable S3 object.  The
S3-backed template is intentionally *not* claimed to be byte-identical to the
historical inline template; only the scaffold properties and captured code
are bound.
"""

from __future__ import annotations

import copy
import hashlib
import io
import re
from dataclasses import dataclass
from collections.abc import Mapping
from types import MappingProxyType
import zipfile

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.aws_retained_dev_prior_code import HANDLER_CODE, MAX_ARCHIVE_BYTES, PriorCodeSnapshot
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_runtime import retained_dev_artifact_bucket

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
HANDLER_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"


class RetainedDevRecoveryBuildError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True, repr=False)
class RetainedDevRecoveryTemplate:
    account_id: str
    bucket: str
    key: str
    original_template_sha256: str
    recovery_template_sha256: str
    code_sha256: str
    code_size_bytes: int
    cfn_role_arn: str
    template: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "template", _freeze(self.template))

    def __repr__(self) -> str:
        return "RetainedDevRecoveryTemplate(private=True)"


def _valid_account(account_id: object) -> bool:
    return type(account_id) is str and _ACCOUNT.fullmatch(account_id) is not None and account_id != "000000000000"


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _validate_archive(body: object) -> tuple[str, int]:
    if type(body) is not bytes or not 1 <= len(body) <= MAX_ARCHIVE_BYTES:
        raise RetainedDevRecoveryBuildError("snapshot_invalid")
    digest = hashlib.sha256(body).hexdigest()
    try:
        with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
            infos = archive.infolist()
            if len(infos) != 1:
                raise ValueError
            info = infos[0]
            mode = (info.external_attr >> 16) & 0o170000
            if (
                info.filename != "index.py"
                or info.flag_bits & 1
                or mode not in (0, 0o100000)
                or info.file_size != len(HANDLER_CODE.encode("utf-8"))
                or archive.read(info) != HANDLER_CODE.encode("utf-8")
            ):
                raise ValueError
    except Exception:
        raise RetainedDevRecoveryBuildError("snapshot_invalid") from None
    return digest, len(body)


def validate_initial_prior_snapshot(snapshot: object) -> PriorCodeSnapshot:
    """Validate the exact captured inline-503 snapshot, without I/O."""
    if not isinstance(snapshot, PriorCodeSnapshot):
        raise RetainedDevRecoveryBuildError("snapshot_invalid")
    expected_template = _canonical(build_retained_dev_template())
    if (
        type(snapshot.template_bytes) is not bytes
        or snapshot.template_bytes != expected_template
        or snapshot.template_sha256 != hashlib.sha256(expected_template).hexdigest()
        or not _SHA256.fullmatch(snapshot.template_sha256)
        or type(snapshot.observed_epoch) is not int
        or snapshot.observed_epoch <= 0
    ):
        raise RetainedDevRecoveryBuildError("snapshot_invalid")
    digest, size = _validate_archive(snapshot.archive_bytes)
    if snapshot.zip_sha256 != digest or not _SHA256.fullmatch(snapshot.zip_sha256):
        raise RetainedDevRecoveryBuildError("snapshot_invalid")
    # Avoid returning the caller's object as a trust claim: rebuild the typed
    # value only after all bytes and hashes have been independently checked.
    return PriorCodeSnapshot(
        archive_bytes=bytes(snapshot.archive_bytes),
        template_bytes=bytes(snapshot.template_bytes),
        zip_sha256=digest,
        template_sha256=snapshot.template_sha256,
        observed_epoch=snapshot.observed_epoch,
    )


def build_initial_recovery_template(account_id: str, snapshot: PriorCodeSnapshot) -> RetainedDevRecoveryTemplate:
    """Build closed S3-backed recovery code and retain the CFN role binding."""
    if not _valid_account(account_id):
        raise RetainedDevRecoveryBuildError("binding_invalid")
    checked = validate_initial_prior_snapshot(snapshot)
    bucket = retained_dev_artifact_bucket(account_id)
    key = f"runtime/{checked.zip_sha256}.zip"
    template = copy.deepcopy(build_retained_dev_template())
    code = template["Resources"]["McpHandler"]["Properties"]["Code"]
    if code != {"ZipFile": HANDLER_CODE}:
        raise RetainedDevRecoveryBuildError("factory_invalid")
    # The initial scaffold remains index.handler, has no Environment, and is
    # closed.  Only the code transport changes to an immutable S3 object.
    props = template["Resources"]["McpHandler"]["Properties"]
    if props.get("Handler") != "index.handler" or "Environment" in props or props.get("ReservedConcurrentExecutions") != 0:
        raise RetainedDevRecoveryBuildError("factory_invalid")
    props["Code"] = {"S3Bucket": bucket, "S3Key": key}
    canonical = _canonical(template)
    return RetainedDevRecoveryTemplate(
        account_id=account_id,
        bucket=bucket,
        key=key,
        original_template_sha256=checked.template_sha256,
        recovery_template_sha256=hashlib.sha256(canonical).hexdigest(),
        code_sha256=checked.zip_sha256,
        code_size_bytes=len(checked.archive_bytes),
        cfn_role_arn=f"arn:aws:iam::{account_id}:role/{CFN_ROLE_NAME}",
        template=template,
    )


def materialize_recovery_template(value: RetainedDevRecoveryTemplate) -> dict[str, object]:
    """Return a fresh mutable JSON-shaped copy for an injected SDK request."""
    if not isinstance(value, RetainedDevRecoveryTemplate):
        raise RetainedDevRecoveryBuildError("template_invalid")
    return _thaw(value.template)  # type: ignore[return-value]


__all__ = [
    "CFN_ROLE_NAME",
    "FUNCTION_NAME",
    "HANDLER_ROLE_NAME",
    "RetainedDevRecoveryBuildError",
    "RetainedDevRecoveryTemplate",
    "build_initial_recovery_template",
    "materialize_recovery_template",
    "validate_initial_prior_snapshot",
]
