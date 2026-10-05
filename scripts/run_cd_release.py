"""Bounded, single-owner production release runner.

This entrypoint rebuilds the runtime from the exact successful CI source SHA,
conditionally publishes its content-addressed ZIP, and delegates every AWS
mutation/readback to the accepted injected production upgrade core. It emits
only fixed categories, source SHA, hashes, phase and call counts. It never
prints bindings, credentials, tokens, SDK output, ZIP contents, or journal data.

The GitHub workflow supplies the private binding JSON through an environment
secret and uses a protected ``prod`` environment for both update and reopen.
AWS credentials are assumed directly from the runner OIDC token into the
fixed executor role; no credential-chain lookup or environment export occurs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from mapit.aws_cd_journal import S3DeliveryJournal
from mapit.aws_prod_geography_upgrade import (
    FUNCTION_NAME,
    REGION,
    SHUTDOWN_NAME,
    STACK_NAME,
    ProdDeliveryAuthorization,
    ProdGeographyUpgrade,
)
from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.config import MapitConfig
from scripts.aws_dev_runtime_artifact import publish_runtime_zip
from scripts.build_aws_prod_runtime import build_prod_runtime_archive
from scripts.github_oidc_claims import validate_oidc_claims, request_runner_oidc_token
from scripts.build_aws_prod_oauth_template import _validate_bucket_name


_MAX_BINDING_BYTES = 32 * 1024
_MAX_AUTHORIZATION_SECONDS = 3600
_MAX_CLOSED_SECONDS = 900
_MAX_CLOSE_POLLS = 20
_MAX_UPDATE_POLLS = 90
_MAX_EMERGENCY_CLOSE_POLLS = 30
_SAFE_CATEGORIES = frozenset({
    "source_context_invalid", "binding_invalid", "oidc_token_invalid",
    "oidc_claims_mismatch", "executor_role_invalid", "sts_exchange_failed",
    "sts_identity_mismatch", "aws_client_unavailable", "journal_unavailable",
    "candidate_build_failed", "candidate_publish_failed", "template_read_failed",
    "artifact_binding_invalid", "authorization_expired", "close_window_expired",
    "core_preflight_failed", "close_failed", "close_pending", "update_failed",
    "update_pending", "reopen_failed", "emergency_close_unverified", "emergency_close_verified",
    "reopen_verified_retention_pending",
    "reopen_verified", "release_ready_for_reopen", "unknown_phase",
    "release_internal_error",
})


class ReleaseError(ValueError):
    def __init__(self, category: str):
        safe = category if type(category) is str and category in _SAFE_CATEGORIES else "release_internal_error"
        self.category = safe
        super().__init__(safe)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _parse_bindings(raw: Any) -> dict[str, Any]:
    if type(raw) is not str or not raw.isascii() or len(raw.encode("ascii")) > _MAX_BINDING_BYTES:
        raise ReleaseError("binding_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise ReleaseError("binding_invalid") from None
    required = {
        "account_id", "stack_arn", "prod_run_id", "api_id", "function_name",
        "shutdown_state_machine_arn", "artifact_bucket", "policy", "mapit_config",
        "parameter_version", "parameter_tier", "jwks", "service_role_arn",
        "executor_role_arn", "owner_id", "repository_id", "initial_service_role_attachment",
        "artifact_tags_sha256",
    }
    if type(value) is not dict or set(value) != required:
        raise ReleaseError("binding_invalid")
    account = value["account_id"]
    if type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None or account == "000000000000":
        raise ReleaseError("binding_invalid")
    if value["function_name"] != FUNCTION_NAME or type(value["function_name"]) is not str:
        raise ReleaseError("binding_invalid")
    if type(value["api_id"]) is not str or re.fullmatch(r"[a-z0-9]{10}", value["api_id"]) is None:
        raise ReleaseError("binding_invalid")
    if value["service_role_arn"] != f"arn:aws:iam::{account}:role/honda-mapit-mcp-prod-cfn-update":
        raise ReleaseError("binding_invalid")
    if value["executor_role_arn"] != f"arn:aws:iam::{account}:role/honda-mapit-mcp-prod-cd-executor":
        raise ReleaseError("executor_role_invalid")
    if type(value["stack_arn"]) is not str or re.fullmatch(
        rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK_NAME}/"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["stack_arn"]
    ) is None:
        raise ReleaseError("binding_invalid")
    if type(value["prod_run_id"]) is not str or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["prod_run_id"]
    ) is None:
        raise ReleaseError("binding_invalid")
    if value["shutdown_state_machine_arn"] != (
        f"arn:aws:states:{REGION}:{account}:stateMachine:{SHUTDOWN_NAME}"
    ):
        raise ReleaseError("binding_invalid")
    if type(value["initial_service_role_attachment"]) is not bool:
        raise ReleaseError("binding_invalid")
    if type(value["artifact_tags_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["artifact_tags_sha256"]) is None:
        raise ReleaseError("binding_invalid")
    try:
        _validate_bucket_name(value["artifact_bucket"])
        policy_data = value["policy"]
        if type(policy_data) is not dict or set(policy_data) != {"user_pool_id", "api_id", "client_id", "owner_subject"}:
            raise ValueError
        if policy_data["api_id"] != value["api_id"]:
            raise ValueError
        policy = CognitoProdPolicy(**policy_data)
        config_data = value["mapit_config"]
        config_fields = {
            "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
            "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
        }
        if type(config_data) is not dict or set(config_data) != config_fields:
            raise ValueError
        config = MapitConfig(**config_data)
        if config.email is not None or config.password is not None or config.discovery_enabled is not False:
            raise ValueError
        if type(value["parameter_version"]) is not int or value["parameter_version"] != 1:
            raise ValueError
        if value["parameter_tier"] != "Standard" or type(value["parameter_tier"]) is not str:
            raise ValueError
        if type(value["owner_id"]) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", value["owner_id"]) is None:
            raise ValueError
        if type(value["repository_id"]) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", value["repository_id"]) is None:
            raise ValueError
        if type(value["jwks"]) is not dict or not value["jwks"]:
            raise ValueError
        value["_validated_policy"] = policy
        value["_validated_mapit_config"] = config
        return value
    except Exception:
        raise ReleaseError("binding_invalid") from None


def _source_context(environ: Mapping[str, str], *, source_sha: str | None = None) -> tuple[str, str]:
    expected_sha = source_sha if source_sha is not None else environ.get("SOURCE_SHA")
    if (
        type(expected_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None
        or environ.get("CHECKED_OUT_SHA") != expected_sha
        or environ.get("GITHUB_REPOSITORY") != "herrerogusano/honda-mapit-mcp"
        or environ.get("GITHUB_REF") != "refs/heads/main"
        or environ.get("TARGET") != "prod"
        or environ.get("GITHUB_ENVIRONMENT") != "prod"
        or type(environ.get("GITHUB_RUN_ID")) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", environ["GITHUB_RUN_ID"]) is None
        or type(environ.get("GITHUB_REPOSITORY_ID")) is not str
        or type(environ.get("GITHUB_REPOSITORY_OWNER_ID")) is not str
    ):
        raise ReleaseError("source_context_invalid")
    return expected_sha, environ["GITHUB_RUN_ID"]


def _reject_ambient_aws(environ: Mapping[str, str]) -> None:
    if any(type(key) is str and (key.startswith("AWS_") or key.startswith("BOTO")) for key in environ):
        raise ReleaseError("aws_client_unavailable")
    try:
        home = Path.home()
        if any((home / ".aws" / name).exists() for name in ("credentials", "config")):
            raise ReleaseError("aws_client_unavailable")
    except ReleaseError:
        raise
    except Exception:
        raise ReleaseError("aws_client_unavailable") from None


def _utc_epoch(clock: Callable[[], float]) -> int:
    value = clock()
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ReleaseError("authorization_expired")
    return int(value)


def _assume_executor(bindings: Mapping[str, Any], source_sha: str, environ: Mapping[str, str], *,
                     opener: Any | None = None, client_factory: Callable[..., Any] | None = None) -> tuple[dict[str, Any], list[Any]]:
    """Verify exact GitHub OIDC claims and return explicit short-lived clients."""
    _reject_ambient_aws(environ)
    try:
        token = request_runner_oidc_token(
            environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
            environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
            opener=opener,
        )
        claims = validate_oidc_claims(
            token, target="prod", source_sha=source_sha,
            expected_repository_id=bindings["repository_id"],
            expected_owner_id=bindings["owner_id"],
        )
    except Exception:
        raise ReleaseError("oidc_claims_mismatch") from None
    clients_created: list[Any] = []
    try:
        if client_factory is None:
            import botocore.session
            from botocore import UNSIGNED
            from botocore.config import Config

            def client_factory(service: str, *, credentials: Mapping[str, str] | None = None, unsigned: bool = False) -> Any:
                session = botocore.session.Session()
                if unsigned:
                    session.set_credentials("", "")
                else:
                    if type(credentials) is not dict or set(credentials) != {
                        "aws_access_key_id", "aws_secret_access_key", "aws_session_token"
                    }:
                        raise ValueError
                    session.set_credentials(
                        credentials["aws_access_key_id"], credentials["aws_secret_access_key"],
                        credentials["aws_session_token"],
                    )
                config = Config(
                    signature_version=UNSIGNED if unsigned else "v4", connect_timeout=2, read_timeout=8,
                    retries={"total_max_attempts": 1, "mode": "standard"}, proxies={},
                )
                endpoint = "https://sts.eu-west-1.amazonaws.com" if service == "sts" else None
                return session.create_client(service, region_name=REGION, endpoint_url=endpoint, verify=True, config=config)
        anonymous = client_factory("sts", unsigned=True)
        clients_created.append(anonymous)
        session_name = f"hm-cd-prod-{source_sha[:16]}"
        assume = anonymous.assume_role_with_web_identity(
            RoleArn=bindings["executor_role_arn"], RoleSessionName=session_name,
            WebIdentityToken=token, DurationSeconds=900,
        )
        status = assume.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(assume, Mapping) else None
        if type(status) is not int or status != 200:
            raise ReleaseError("sts_exchange_failed")
        expected_provider = f"arn:aws:iam::{bindings['account_id']}:oidc-provider/token.actions.githubusercontent.com"
        if (
            assume.get("Provider") not in {"https://token.actions.githubusercontent.com", expected_provider}
            or assume.get("Audience") != "sts.amazonaws.com"
            or type(assume.get("SubjectFromWebIdentityToken")) is not str
            or hashlib.sha256(assume["SubjectFromWebIdentityToken"].encode("utf-8")).hexdigest() != claims.subject_sha256
        ):
            raise ReleaseError("sts_identity_mismatch")
        expected_arn = (
            f"arn:aws:sts::{bindings['account_id']}:assumed-role/"
            f"honda-mapit-mcp-prod-cd-executor/{session_name}"
        )
        assumed = assume.get("AssumedRoleUser")
        credentials = assume.get("Credentials")
        if not isinstance(assumed, Mapping) or assumed.get("Arn") != expected_arn or not isinstance(credentials, Mapping):
            raise ReleaseError("sts_identity_mismatch")
        access = credentials.get("AccessKeyId")
        secret = credentials.get("SecretAccessKey")
        session_token = credentials.get("SessionToken")
        expires = credentials.get("Expiration")
        if any(type(item) is not str or not item or len(item) > 4096 for item in (access, secret, session_token)):
            raise ReleaseError("sts_identity_mismatch")
        if not isinstance(expires, datetime) or expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise ReleaseError("sts_identity_mismatch")
        explicit = {"aws_access_key_id": access, "aws_secret_access_key": secret, "aws_session_token": session_token}
        signed_sts = client_factory("sts", credentials=explicit, unsigned=False)
        clients_created.append(signed_sts)
        caller = signed_sts.get_caller_identity()
        caller_status = caller.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(caller, Mapping) else None
        if (
            type(caller_status) is not int or caller_status != 200
            or caller.get("Account") != bindings["account_id"] or caller.get("Arn") != expected_arn
            or caller.get("UserId") != assumed.get("AssumedRoleId")
        ):
            raise ReleaseError("sts_identity_mismatch")
        services: dict[str, Any] = {"sts": signed_sts}
        for service in ("cloudformation", "apigatewayv2", "lambda", "stepfunctions", "cloudwatch", "events", "s3"):
            client = client_factory(service, credentials=explicit, unsigned=False)
            clients_created.append(client)
            services[service] = client
        return services, clients_created
    except ReleaseError:
        for client in clients_created:
            try:
                client.close()
            except Exception:
                pass
        raise
    except Exception:
        for client in clients_created:
            try:
                client.close()
            except Exception:
                pass
        raise ReleaseError("sts_exchange_failed") from None


def _http_200(reply: Any) -> bool:
    metadata = reply.get("ResponseMetadata") if isinstance(reply, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata[
        "HTTPStatusCode"
    ] == 200


def _verify_private_artifact_bucket(s3: Any, bucket: str, account_id: str, *, tag_fingerprint: str | None = None) -> bool:
    """Read back the bounded storage controls before publishing any artifact."""
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket, ExpectedBucketOwner=account_id)
        location = s3.get_bucket_location(Bucket=bucket, ExpectedBucketOwner=account_id)
        public = s3.get_public_access_block(Bucket=bucket, ExpectedBucketOwner=account_id)
        ownership = s3.get_bucket_ownership_controls(Bucket=bucket, ExpectedBucketOwner=account_id)
        encryption = s3.get_bucket_encryption(Bucket=bucket, ExpectedBucketOwner=account_id)
        policy_status = s3.get_bucket_policy_status(Bucket=bucket, ExpectedBucketOwner=account_id)
        bucket_policy = s3.get_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account_id)
        tagging = s3.get_bucket_tagging(Bucket=bucket, ExpectedBucketOwner=account_id)
        p = public.get("PublicAccessBlockConfiguration") if isinstance(public, Mapping) else None
        o = ownership.get("OwnershipControls", {}).get("Rules") if isinstance(ownership, Mapping) else None
        e = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules") if isinstance(encryption, Mapping) else None
        t = tagging.get("TagSet") if isinstance(tagging, Mapping) else None
        policy_text = bucket_policy.get("Policy") if isinstance(bucket_policy, Mapping) else None
        policy_doc = json.loads(policy_text, object_pairs_hook=_pairs) if type(policy_text) is str else None
        bucket_arn = f"arn:aws:s3:::{bucket}"
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny",
                "Principal": "*", "Action": "s3:*", "Resource": [bucket_arn, bucket_arn + "/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }],
        }
        core_tags = {"Project": "honda-mapit-mcp", "Environment": "prod", "Purpose": "production-runtime-artifact"}
        tag_map: dict[str, str] = {}
        if type(t) is list and len(t) <= 10:
            for item in t:
                if (
                    not isinstance(item, Mapping) or type(item.get("Key")) is not str
                    or type(item.get("Value")) is not str or item["Key"] in tag_map
                    or not item["Key"].isascii() or not item["Value"].isascii()
                    or len(item["Key"]) > 128 or len(item["Value"]) > 256
                ):
                    tag_map = {}
                    break
                tag_map[item["Key"]] = item["Value"]
        normalized_tags = [{"Key": key, "Value": value} for key, value in sorted(tag_map.items())]
        tags_match = (
            set(tag_map.items()) >= set(core_tags.items())
            and (tag_fingerprint is None or (
                type(tag_fingerprint) is str and re.fullmatch(r"[0-9a-f]{64}", tag_fingerprint) is not None
                and hashlib.sha256(_canonical(normalized_tags)).hexdigest() == tag_fingerprint
            ))
        )
        return (
            all(_http_200(reply) for reply in (versioning, location, public, ownership, encryption, policy_status, bucket_policy, tagging))
            and isinstance(versioning, Mapping) and versioning.get("Status") is None
            and isinstance(location, Mapping) and location.get("LocationConstraint") == REGION
            and isinstance(p, Mapping) and all(p.get(key) is True for key in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
            ))
            and type(o) is list and o == [{"ObjectOwnership": "BucketOwnerEnforced"}]
            and type(e) is list and len(e) == 1
            and isinstance(e[0], Mapping)
            and e[0].get("ApplyServerSideEncryptionByDefault") == {"SSEAlgorithm": "AES256"}
            and policy_status.get("PolicyStatus", {}).get("IsPublic") is False
            and isinstance(policy_doc, Mapping) and _canonical(policy_doc) == _canonical(expected_policy)
            and tags_match
        )
    except Exception:
        return False


def _old_artifact_binding(clients: Mapping[str, Any], stack_arn: str) -> tuple[str, str]:
    try:
        response = clients["cloudformation"].get_template(StackName=stack_arn, TemplateStage="Original")
    except Exception:
        raise ReleaseError("template_read_failed") from None
    if not _http_200(response):
        raise ReleaseError("template_read_failed")
    body = response.get("TemplateBody")
    if type(body) is str:
        try:
            body = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except Exception:
            raise ReleaseError("artifact_binding_invalid") from None
    try:
        function = body["Resources"]["McpHandler"]["Properties"]
        code = function["Code"]
        variables = function["Environment"]["Variables"]
        key = code["S3Key"]
        manifest = variables["MAPIT_PROD_MANIFEST_SHA256"]
        match = re.fullmatch(r"runtime/([0-9a-f]{64})\.zip", key) if type(key) is str else None
        if (
            not isinstance(body, Mapping) or match is None
            or type(manifest) is not str or re.fullmatch(r"[0-9a-f]{64}", manifest) is None
            or code.get("S3Bucket") is None
        ):
            raise ValueError
        return match.group(1), manifest
    except Exception:
        raise ReleaseError("artifact_binding_invalid") from None


def _manifest_sha(archive_path: Path) -> str:
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            info = archive.getinfo("mapit/mapit-prod.manifest.json")
            if info.file_size > 8192:
                raise ValueError
            raw = archive.read(info)
        value = json.loads(raw, object_pairs_hook=_pairs)
        if type(value) is not dict or value.get("environment") != "prod" or value.get("region") != REGION:
            raise ValueError
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        raise ReleaseError("candidate_build_failed") from None


def _core(bindings: Mapping[str, Any], services: Mapping[str, Any], journal: Any, *,
          run_id: str, source_sha: str, old_zip: str, old_manifest: str,
          new_zip: str, new_manifest: str, authorized_from: int, authorized_until: int,
          wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> ProdGeographyUpgrade:
    auth = ProdDeliveryAuthorization(
        source_sha=source_sha, authorized_from_epoch=authorized_from,
        authorized_until_epoch=authorized_until, service_role_arn=bindings["service_role_arn"],
        initial_service_role_attachment=bindings["initial_service_role_attachment"],
    )
    return ProdGeographyUpgrade(
        services, journal, policy=bindings["_validated_policy"], account_id=bindings["account_id"],
        stack_arn=bindings["stack_arn"], prod_run_id=bindings["prod_run_id"],
        api_id=bindings["api_id"], function_name=bindings["function_name"],
        shutdown_state_machine_arn=bindings["shutdown_state_machine_arn"], bucket=bindings["artifact_bucket"],
        old_zip_sha256=old_zip, old_manifest_sha256=old_manifest,
        new_zip_sha256=new_zip, new_manifest_sha256=new_manifest,
        authorized_until_epoch=authorized_until, authorized_from_epoch=authorized_from,
        delivery_authorization=auth, wall_clock=wall_clock, monotonic=monotonic,
    )


def _journal_state(journal: S3DeliveryJournal) -> dict[str, Any]:
    try:
        with journal.locked():
            value = journal.load()
        if type(value) is not dict:
            raise ValueError
        return value
    except Exception:
        raise ReleaseError("journal_unavailable") from None


def _close_age(services: Mapping[str, Any], state: Mapping[str, Any], *, now: Callable[[], float]) -> bool:
    intent = state.get("close_intent")
    if not isinstance(intent, Mapping) or type(intent.get("execution_arn")) is not str:
        return False
    try:
        result = services["stepfunctions"].describe_execution(executionArn=intent["execution_arn"])
        status = result.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(result, Mapping) else None
        start = result.get("startDate") if isinstance(result, Mapping) else None
        if type(status) is not int or status != 200 or not isinstance(start, datetime):
            return False
        if start.tzinfo is None or start.utcoffset() is None:
            return False
        current = now()
        delta = current - start.astimezone(timezone.utc).timestamp()
        return (
            type(current) in (int, float) and not isinstance(current, bool)
            and math.isfinite(current) and 0 <= delta <= _MAX_CLOSED_SECONDS
        )
    except Exception:
        return False


class CDReleaseRunner:
    """One-shot CLI adapter; clients/build inputs remain explicit and private."""

    def __init__(self, *, environ: Mapping[str, str] | None = None,
                 opener: Any | None = None, clock: Callable[[], float] = time.time,
                 client_factory: Callable[..., Any] | None = None):
        self.environ = os.environ if environ is None else environ
        self.opener = opener
        self.clock = clock
        self.client_factory = client_factory

    def run(self, phase: str) -> dict[str, Any]:
        if type(phase) is not str or phase not in {"build-update", "reopen", "recover-close"}:
            return {"status": "failed", "phase": "unknown", "category": "unknown_phase"}
        clients: list[Any] = []
        scratch_context: Any | None = None
        try:
            _reject_ambient_aws(self.environ)
            source_sha, run_id = _source_context(self.environ)
            self._source_sha = source_sha
            raw = self.environ.get("MAPIT_CD_BINDING_JSON")
            bindings = _parse_bindings(raw)
            candidate = None
            if phase == "build-update":
                # Complete the private deterministic build before requesting
                # a runner OIDC token or constructing any AWS client.
                scratch_context = tempfile.TemporaryDirectory(prefix="mapit-cd-")
                candidate = self._build_candidate(bindings, Path(scratch_context.name))
            services, clients = _assume_executor(
                bindings, source_sha, self.environ, opener=self.opener, client_factory=self.client_factory,
            )
            journal = S3DeliveryJournal(
                services["s3"], bucket=bindings["artifact_bucket"], account_id=bindings["account_id"],
                run_id=run_id, source_sha=source_sha,
            )
            if phase == "build-update":
                assert candidate is not None
                result = self._build_and_update(bindings, services, journal, run_id, source_sha, candidate)
            else:
                result = self._reopen_or_close(phase, bindings, services, journal, run_id, source_sha)
            return result
        except ReleaseError as exc:
            return {"status": "failed", "phase": phase, "category": exc.category}
        except Exception:
            return {"status": "failed", "phase": phase, "category": "release_internal_error"}
        finally:
            for client in clients:
                try:
                    client.close()
                except Exception:
                    pass
            if scratch_context is not None:
                try:
                    scratch_context.cleanup()
                except Exception:
                    pass

    def _build_candidate(self, bindings: Mapping[str, Any], scratch: Path) -> tuple[Path, Any, str]:
        wheel_dir = self.environ.get("MAPIT_CD_RUNTIME_WHEEL_DIR")
        geography_dir = self.environ.get("MAPIT_CD_GEOGRAPHY_WHEEL_DIR")
        if type(wheel_dir) is not str or type(geography_dir) is not str:
            raise ReleaseError("candidate_build_failed")
        try:
            jwks_path = scratch / "public-jwks.json"
            archive_path = scratch / "runtime.zip"
            jwks_path.write_bytes(_canonical(bindings["jwks"]))
            summary = build_prod_runtime_archive(
                Path(wheel_dir), jwks_path, archive_path,
                policy=bindings["_validated_policy"],
                mapit_config=bindings["_validated_mapit_config"],
                account_id=bindings["account_id"],
                parameter_version=bindings["parameter_version"],
                parameter_tier=bindings["parameter_tier"],
                source_sha=self._source_sha,
                geography_wheel_dir=Path(geography_dir),
            )
            manifest_sha = _manifest_sha(archive_path)
            from scripts.probe_cd_candidate import probe_candidate
            if not probe_candidate(archive_path, zip_sha256=summary.sha256,
                                   manifest_sha256=manifest_sha, source_sha=self._source_sha,
                                   report=lambda checks: print(json.dumps({"offline_arm_checks": checks}, sort_keys=True))):
                raise ReleaseError("candidate_build_failed")
            return archive_path, summary, manifest_sha
        except ReleaseError:
            raise
        except Exception:
            raise ReleaseError("candidate_build_failed") from None

    def _build_and_update(self, bindings: Mapping[str, Any], services: Mapping[str, Any], journal: S3DeliveryJournal,
                          run_id: str, source_sha: str, candidate: tuple[Path, Any, str]) -> dict[str, Any]:
        archive_path, summary, manifest_sha = candidate
        try:
            old_zip, old_manifest = _old_artifact_binding(services, bindings["stack_arn"])
            now = _utc_epoch(self.clock)
            auth_end = now + _MAX_AUTHORIZATION_SECONDS
            core = _core(
                bindings, services, journal, run_id=run_id, source_sha=source_sha,
                old_zip=old_zip, old_manifest=old_manifest, new_zip=summary.sha256,
                new_manifest=manifest_sha, authorized_from=now, authorized_until=auth_end,
                wall_clock=self.clock,
            )
            result = core.run_step("preflight")
            if result.get("category") != "preflight_verified":
                raise ReleaseError("core_preflight_failed")
            if not _verify_private_artifact_bucket(
                services["s3"], bindings["artifact_bucket"], bindings["account_id"],
                tag_fingerprint=bindings["artifact_tags_sha256"],
            ):
                raise ReleaseError("candidate_publish_failed")
            published = publish_runtime_zip(
                services["s3"], bucket=bindings["artifact_bucket"],
                expected_owner=bindings["account_id"], archive_path=archive_path,
                sha256_hex=summary.sha256, size_bytes=summary.zip_bytes,
            )
            if not published.success or published.category not in {
                "artifact_uploaded_verified", "artifact_already_present_verified",
            }:
                raise ReleaseError("candidate_publish_failed")
        except ReleaseError:
            raise
        except Exception:
            raise ReleaseError("candidate_build_failed") from None

        close = core.run_step("close")
        if close.get("category") != "close_pending":
            raise ReleaseError("close_failed")
        verified_close = False
        for attempt in range(_MAX_CLOSE_POLLS):
            check = core.run_step("check-close")
            if check.get("verified") is True:
                verified_close = True
                break
            if check.get("category") != "close_pending":
                raise ReleaseError("close_failed")
            if attempt + 1 < _MAX_CLOSE_POLLS:
                time.sleep(2)
        if not verified_close:
            return {"status": "pending", "phase": "check-close", "category": "close_pending",
                    "source_sha": source_sha, "artifact_sha256": summary.sha256,
                    "manifest_sha256": manifest_sha, "authorization_start": now,
                    "authorization_until": auth_end}
        close_state = _journal_state(journal)
        if not _close_age(services, close_state, now=self.clock):
            raise ReleaseError("close_window_expired")
        update = core.run_step("request-update")
        if update.get("category") != "update_pending":
            raise ReleaseError("update_failed")
        updated = False
        for attempt in range(_MAX_UPDATE_POLLS):
            if not _close_age(services, close_state, now=self.clock):
                raise ReleaseError("close_window_expired")
            check = core.run_step("check-update")
            if check.get("verified") is True:
                updated = True
                break
            if check.get("category") != "update_pending":
                raise ReleaseError("update_failed")
            if attempt + 1 < _MAX_UPDATE_POLLS:
                time.sleep(2)
        if not updated:
            return {"status": "pending", "phase": "check-update", "category": "update_pending",
                    "source_sha": source_sha, "artifact_sha256": summary.sha256,
                    "manifest_sha256": manifest_sha, "authorization_start": now,
                    "authorization_until": auth_end}
        return {"status": "awaiting_approval", "phase": "update_verified",
                "category": "release_ready_for_reopen", "source_sha": source_sha,
                "artifact_sha256": summary.sha256, "manifest_sha256": manifest_sha,
                "authorization_start": now, "authorization_until": auth_end}

    def _reopen_or_close(self, phase: str, bindings: Mapping[str, Any], services: Mapping[str, Any],
                         journal: S3DeliveryJournal, run_id: str, source_sha: str) -> dict[str, Any]:
        state = _journal_state(journal)
        delivery = state.get("delivery_binding")
        if (
            state.get("kind") != "prod_cd_delivery" or state.get("prod_run_id") != bindings["prod_run_id"]
            or not isinstance(delivery, Mapping) or delivery.get("source_sha") != source_sha
            or delivery.get("service_role_arn") != bindings["service_role_arn"]
            or delivery.get("initial_service_role_attachment") is not bindings["initial_service_role_attachment"]
            or state.get("authorization_start_epoch") is None
        ):
            raise ReleaseError("journal_unavailable")
        start, end = state.get("authorization_start_epoch"), state.get("authorization_cutoff_epoch")
        if type(start) is not int or type(end) is not int or not 1 <= end - start <= _MAX_AUTHORIZATION_SECONDS:
            raise ReleaseError("authorization_expired")
        core = _core(
            bindings, services, journal, run_id=run_id, source_sha=source_sha,
            old_zip=state.get("old_zip_sha256"), old_manifest=state.get("old_manifest_sha256"),
            new_zip=state.get("new_zip_sha256"), new_manifest=state.get("new_manifest_sha256"),
            authorized_from=start, authorized_until=end, wall_clock=self.clock,
        )
        if phase == "recover-close":
            result = self._emergency_close(services, bindings)
            if result:
                return {"status": "verified", "phase": "recover-close", "category": "emergency_close_verified"}
            raise ReleaseError("emergency_close_unverified")
        for key, expected in (
            ("AUTHORIZATION_START", start), ("AUTHORIZATION_UNTIL", end),
            ("ARTIFACT_SHA256", state.get("new_zip_sha256")),
            ("MANIFEST_SHA256", state.get("new_manifest_sha256")),
        ):
            supplied = self.environ.get(key)
            if supplied is None:
                continue
            if type(expected) is int:
                if type(supplied) is not str or re.fullmatch(r"[1-9][0-9]{0,12}", supplied) is None or int(supplied) != expected:
                    raise ReleaseError("journal_unavailable")
            elif type(supplied) is not str or supplied != expected:
                raise ReleaseError("journal_unavailable")
        if not _close_age(services, state, now=self.clock):
            raise ReleaseError("close_window_expired")
        result = core.run_step("open")
        if result.get("category") == "production_open_verified" and result.get("verified") is True:
            # Tag only a fresh, fully verified terminal journal. A tagging
            # failure must not close a service whose reopen has already been
            # independently verified; it instead leaves retention pending.
            latest = _journal_state(journal)
            if latest.get("production_open_verified") is not True:
                raise ReleaseError("reopen_failed")
            if not self._tag_terminal_journal(journal, bindings):
                return {"status": "verified", "phase": "reopen",
                        "category": "reopen_verified_retention_pending",
                        "source_sha": source_sha, "artifact_sha256": state["new_zip_sha256"],
                        "manifest_sha256": state["new_manifest_sha256"]}
            return {"status": "verified", "phase": "reopen", "category": "reopen_verified",
                    "source_sha": source_sha, "artifact_sha256": state["new_zip_sha256"],
                    "manifest_sha256": state["new_manifest_sha256"]}
        if self._emergency_close(services, bindings):
            raise ReleaseError("reopen_failed")
        raise ReleaseError("emergency_close_unverified")

    def _tag_terminal_journal(self, journal: S3DeliveryJournal, bindings: Mapping[str, Any]) -> bool:
        """Apply the exact lifecycle marker only to this verified journal object."""
        try:
            if (
                type(getattr(journal, "key", None)) is not str
                or journal.key != f"journals/{self.environ.get('GITHUB_RUN_ID')}.json"
                or journal.bucket != bindings["artifact_bucket"]
                or journal.account_id != bindings["account_id"]
            ):
                return False
            client = journal.client
            observed = client.get_object_tagging(
                Bucket=journal.bucket, Key=journal.key, ExpectedBucketOwner=journal.account_id,
            )
            if not _http_200(observed) or type(observed.get("TagSet")) is not list:
                return False
            tag_set = observed["TagSet"]
            expected = [{"Key": "cd-terminal", "Value": "true"}]
            if tag_set == expected:
                return True
            if tag_set != []:
                return False
            written = client.put_object_tagging(
                Bucket=journal.bucket, Key=journal.key,
                ExpectedBucketOwner=journal.account_id,
                Tagging={"TagSet": expected},
            )
            if not _http_200(written):
                return False
            verified = client.get_object_tagging(
                Bucket=journal.bucket, Key=journal.key, ExpectedBucketOwner=journal.account_id,
            )
            return _http_200(verified) and type(verified.get("TagSet")) is list and verified["TagSet"] == expected
        except Exception:
            return False

    def _emergency_close(self, services: Mapping[str, Any], bindings: Mapping[str, Any]) -> bool:
        """Start one fresh independent shutdown execution; never retry it."""
        name = str(uuid.uuid4())
        try:
            from scripts.build_aws_prod_controls import fixed_prod_controls_template

            machine = services["stepfunctions"].describe_state_machine(
                stateMachineArn=bindings["shutdown_state_machine_arn"],
            )
            if not _http_200(machine):
                return False
            definition = machine.get("definition")
            parsed = json.loads(definition, object_pairs_hook=_pairs) if type(definition) is str else None
            expected_definition = fixed_prod_controls_template(bindings["api_id"])["Resources"][
                "ShutdownStateMachine"
            ]["Properties"]["DefinitionString"]
            expected_parsed = json.loads(expected_definition, object_pairs_hook=_pairs)
            if (
                machine.get("stateMachineArn") != bindings["shutdown_state_machine_arn"]
                or machine.get("name") != SHUTDOWN_NAME or machine.get("type") != "STANDARD"
                or machine.get("roleArn") != (
                    f"arn:aws:iam::{bindings['account_id']}:role/honda-mapit-mcp-prod-shutdown-workflow"
                )
                or not isinstance(parsed, Mapping)
                or _canonical(parsed) != _canonical(expected_parsed)
            ):
                return False
        except Exception:
            return False
        expected_arn = (
            f"arn:aws:states:{REGION}:{bindings['account_id']}:execution:{SHUTDOWN_NAME}:{name}"
        )
        try:
            reply = services["stepfunctions"].start_execution(
                stateMachineArn=bindings["shutdown_state_machine_arn"], name=name, input="{}",
            )
            if not _http_200(reply) or reply.get("executionArn") != expected_arn:
                return False
            check = None
            for attempt in range(_MAX_EMERGENCY_CLOSE_POLLS):
                check = services["stepfunctions"].describe_execution(executionArn=expected_arn)
                if not _http_200(check) or check.get("executionArn") != expected_arn:
                    return False
                status = check.get("status")
                if status in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}:
                    break
                if status != "RUNNING" or attempt + 1 >= _MAX_EMERGENCY_CLOSE_POLLS:
                    return False
                time.sleep(2)
            if check is None or check.get("status") != "SUCCEEDED":
                return False
            output = check.get("output")
            if type(output) is str:
                output = json.loads(output, object_pairs_hook=_pairs)
            if (
                type(output) is not dict
                or output.get("verified") is not True or output.get("api_closed") is not True
                or output.get("function_reserved") is not True
                or output.get("api_write_call_returned") is not True
                or output.get("function_write_call_returned") is not True
            ):
                return False
            api = services["apigatewayv2"].get_api(ApiId=bindings["api_id"])
            concurrency = services["lambda"].get_function_concurrency(FunctionName=FUNCTION_NAME)
            return (
                _http_200(api) and api.get("ApiId") == bindings["api_id"]
                and api.get("DisableExecuteApiEndpoint") is True
                and _http_200(concurrency)
                and type(concurrency.get("ReservedConcurrentExecutions")) is int
                and concurrency.get("ReservedConcurrentExecutions") == 0
            )
        except Exception:
            return False


def _emit_outputs(result: Mapping[str, Any], environ: Mapping[str, str]) -> None:
    target = environ.get("GITHUB_OUTPUT")
    if type(target) is not str or not target:
        return
    allowed = {"artifact_sha256", "manifest_sha256", "authorization_start", "authorization_until"}
    values = {key: result.get(key) for key in allowed if key in result}
    if "category" in result:
        values["ready"] = "true" if result.get("category") == "release_ready_for_reopen" else "false"
    if any(type(value) is not str and type(value) is not int for value in values.values()):
        raise ReleaseError("release_internal_error")
    try:
        with open(target, "a", encoding="utf-8", newline="\n") as stream:
            for key in sorted(values):
                stream.write(f"{key}={values[key]}\n")
    except Exception:
        raise ReleaseError("release_internal_error") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one approved production release phase.")
    parser.add_argument("phase", choices=("build-update", "reopen", "recover-close"))
    args = parser.parse_args(argv)
    runner = CDReleaseRunner()
    result = runner.run(args.phase)
    try:
        _emit_outputs(result, os.environ)
        print(json.dumps(result, separators=(",", ":"), allow_nan=False))
    except Exception:
        print('{"status":"failed","phase":"unknown","category":"release_internal_error"}')
        return 1
    return 0 if result.get("status") in {"verified", "awaiting_approval", "pending"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
