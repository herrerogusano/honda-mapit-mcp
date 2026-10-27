"""One-shot create-only key handoff for the separate DEV MAPIT namespace.

This injected operator core creates no SDK clients and performs no credential
discovery. It is deliberately separate from the historical synthetic key
publisher and its consumed journals.
"""
from __future__ import annotations

import math
import re
import time
from typing import Any, Mapping

from mapit.aws_binding_keys import (
    MAPIT_PARAMETER_PATH,
    BindingKeyMaterial,
    encode_binding_keys,
    generate_binding_keys,
    load_binding_keys,
)
from mapit.cloud_transport import validate_cloud_config
from mapit.config import MapitConfig
from scripts.build_aws_dev_mapit_binding_bootstrap import OPERATOR_ROLE_NAME

REGION = "eu-west-1"
MAX_STEP_SECONDS = 14.0
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SESSION = re.compile(r"[A-Za-z0-9+=,.@_-]{2,64}\Z")
_CATEGORIES = frozenset({
    "key_publication_invalid", "key_publication_unauthorized", "key_publication_consumed",
    "key_publication_preflight_failed", "key_publication_exists", "key_publication_intent_failed",
    "key_publication_outcome_unknown", "key_publication_unverified", "key_publication_verified",
})


def _client_valid(client: Any, service: str) -> bool:
    try:
        meta = client.meta
        config = meta.config
        endpoint = f"https://{service}.{REGION}.amazonaws.com"
        return (
            meta.service_model.service_name == service
            and meta.region_name == REGION
            and meta.endpoint_url == endpoint
            and isinstance(config.retries, Mapping)
            and type(config.retries.get("total_max_attempts")) is int
            and config.retries["total_max_attempts"] == 1
            and config.signature_version == "v4"
            and isinstance(config.proxies, Mapping) and len(config.proxies) == 0
            and all(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 3
                    for value in (config.connect_timeout, config.read_timeout))
            and client._endpoint.http_session._verify is True
        )
    except Exception:
        return False


def _response_ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping)
            and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


def _exact_assumed_role(clients: Mapping[str, Any], account_id: str) -> bool:
    """Verify one fresh STS identity through the pinned enroller role."""
    try:
        response = clients["sts"].get_caller_identity()
        if not _response_ok(response) or response.get("Account") != account_id:
            return False
        arn = response.get("Arn")
        match = (re.fullmatch(
            rf"arn:aws:sts::{account_id}:assumed-role/{re.escape(OPERATOR_ROLE_NAME)}/(.+)",
            arn,
        ) if type(arn) is str else None)
        return match is not None and _SESSION.fullmatch(match.group(1)) is not None
    except Exception:
        return False


def publish_mapit_keys(
    clients: Mapping[str, Any],
    journal: Any,
    *,
    account_id: str,
    config: MapitConfig,
    source_sha: str,
    run_id: int,
    bootstrap_sha256: str,
    start: int,
    end: int,
    clock=time.time,
    monotonic=time.monotonic,
) -> dict[str, Any]:
    """Publish schema-2 MAPIT binding keys exactly once at version one.

    The caller must bind ``bootstrap_sha256`` to a separately accepted
    ``build_aws_dev_mapit_binding_bootstrap`` receipt and must perform fresh
    source/protection checks. The injected STS and SSM clients must be
    constructed from the same explicit short-lived assumed-role credentials by
    the trusted caller; role-shaped STS output alone cannot prove credential
    parity. A possibly dispatched write always consumes this journal; this
    function never retries, overwrites, deletes, or rotates it.
    """
    category = "key_publication_invalid"
    material = None
    encoded = None
    try:
        if (
            not isinstance(clients, Mapping) or set(clients) != {"sts", "ssm"}
            or type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "0" * 12
            or type(config) is not MapitConfig or config.email is not None or config.password is not None
            or type(source_sha) is not str or _SOURCE.fullmatch(source_sha) is None or source_sha == "0" * 40
            or type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0
            or type(bootstrap_sha256) is not str or _SHA.fullmatch(bootstrap_sha256) is None
            or type(start) is not int or isinstance(start, bool)
            or type(end) is not int or isinstance(end, bool) or not 0 < start < end
            or not 0 < end - start <= 3600
            or not callable(clock) or not callable(monotonic)
            or not _client_valid(clients["sts"], "sts")
            or not _client_valid(clients["ssm"], "ssm")
            or not all(callable(getattr(journal, name, None)) for name in ("locked", "load", "save"))
        ):
            raise ValueError
        validate_cloud_config(config)
        if config.frontend_url != "https://app.mapit.me/":
            raise ValueError

        started = monotonic()
        if type(started) not in (int, float) or isinstance(started, bool) or not math.isfinite(started):
            raise ValueError
        last_mono = float(started)
        last_epoch = 0.0

        def fresh() -> None:
            nonlocal last_mono, last_epoch
            now = monotonic()
            epoch = clock()
            if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                    or now < last_mono or now - started >= MAX_STEP_SECONDS
                    or type(epoch) not in (int, float) or isinstance(epoch, bool) or not math.isfinite(epoch)
                    or epoch < last_epoch or not start <= epoch < end):
                raise ValueError
            last_mono = float(now)
            last_epoch = float(epoch)

        parameter_arn = f"arn:aws:ssm:{REGION}:{account_id}:parameter{MAPIT_PARAMETER_PATH}"
        intent = {
            "schema": 1,
            "operation": "dev_mapit_binding_key_publication",
            "namespace": "mapit",
            "account": account_id,
            "source": source_sha,
            "run_id": run_id,
            "bootstrap_sha256": bootstrap_sha256,
            "parameter_path": MAPIT_PARAMETER_PATH,
            "start": start,
            "end": end,
            "phase": "put_intent",
        }
        with journal.locked():
            if journal.load() is not None:
                return {"ok": False, "category": "key_publication_consumed"}
            category = "key_publication_unauthorized"
            fresh()
            if not _exact_assumed_role(clients, account_id):
                raise ValueError
            fresh()

            category = "key_publication_preflight_failed"
            try:
                clients["ssm"].get_parameter(Name=MAPIT_PARAMETER_PATH, WithDecryption=False)
            except Exception as exc:
                response = getattr(exc, "response", None)
                error = response.get("Error") if isinstance(response, Mapping) else None
                metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
                if (not isinstance(error, Mapping) or error.get("Code") != "ParameterNotFound"
                        or not isinstance(metadata, Mapping)
                        or type(metadata.get("HTTPStatusCode")) is not int
                        or metadata["HTTPStatusCode"] != 400):
                    raise ValueError from None
            else:
                category = "key_publication_exists"
                raise ValueError
            fresh()
            if not _exact_assumed_role(clients, account_id):
                category = "key_publication_unauthorized"
                raise ValueError
            fresh()

            # Construct one candidate only after checking that this durable
            # authority is unused and the target path is absent. Codec/config
            # validation still completes before writing the intent.
            material = generate_binding_keys()
            if type(material) is not BindingKeyMaterial:
                raise ValueError
            encoded = encode_binding_keys(material, account_id=account_id, config=config,
                                          namespace="mapit", environment="dev")
            if type(encoded) is not str or not encoded:
                raise ValueError

            category = "key_publication_intent_failed"
            journal.save(intent)
            fresh()

            category = "key_publication_outcome_unknown"
            if not _exact_assumed_role(clients, account_id):
                raise ValueError
            fresh()
            acknowledgement = clients["ssm"].put_parameter(
                Name=MAPIT_PARAMETER_PATH, Value=encoded, Type="SecureString",
                KeyId="alias/aws/ssm", Overwrite=False, Tier="Standard", DataType="text",
            )
            fresh()
            if (not _response_ok(acknowledgement)
                    or type(acknowledgement.get("Version")) is not int
                    or acknowledgement["Version"] != 1
                    or acknowledgement.get("Tier") != "Standard"):
                raise ValueError

            category = "key_publication_unverified"
            latest = clients["ssm"].get_parameter(Name=MAPIT_PARAMETER_PATH, WithDecryption=False)
            fresh()
            parameter = latest.get("Parameter") if isinstance(latest, Mapping) else None
            if (not _response_ok(latest) or not isinstance(parameter, Mapping)
                    or parameter.get("Name") != MAPIT_PARAMETER_PATH
                    or parameter.get("ARN") != parameter_arn
                    or parameter.get("Type") != "SecureString"
                    or parameter.get("DataType") != "text"
                    or type(parameter.get("Version")) is not int or parameter["Version"] != 1
                    or "Selector" in parameter or "SourceResult" in parameter
                    or any(key in latest for key in ("NextToken", "NextMarker", "Marker"))):
                raise ValueError

            def account_verifier(client: Any, expected: str) -> bool:
                fresh()
                allowed = client is clients["ssm"] and expected == account_id and _exact_assumed_role(clients, account_id)
                fresh()
                return allowed

            loaded = load_binding_keys(
                clients["ssm"], account_id=account_id, config=config,
                account_verifier=account_verifier, deadline=started + MAX_STEP_SECONDS,
                monotonic=monotonic, namespace="mapit", environment="dev",
            )
            fresh()
            if loaded != material:
                raise ValueError
            accepted = dict(intent)
            accepted["phase"] = "accepted"
            journal.save(accepted)
            fresh()
            return {"ok": True, "category": "key_publication_verified"}
    except Exception:
        return {"ok": False, "category": category if category in _CATEGORIES else "key_publication_unverified"}
    finally:
        # Drop local references on every path. Python immutable bytes cannot be
        # reliably zeroized; this is best-effort lifetime reduction only.
        material = None
        encoded = None


__all__ = ["publish_mapit_keys"]
