"""Pure opt-in DEV enrolled-runtime manifest; no clients or secret material.

The manifest pins two independent public JWT key sets and a finite invitation
list. It is private deployment metadata, not a bearer credential or proof that
its resources have been provisioned or that MAPIT has accepted any login.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Mapping

from .aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from .cloud_transport import validate_cloud_config
from .config import MapitConfig

MAX_MANIFEST_BYTES = 24 * 1024
MAX_JWKS_BYTES = 32 * 1024
MANIFEST_FILENAME = "dev-enrolled.manifest.json"
INVITATION_JWKS_FILENAME = "dev-enrolled-invitation.jwks.json"
MAPIT_JWKS_FILENAME = "dev-enrolled-mapit.jwks.json"
_FIELDS = frozenset({"schema", "builder", "environment", "mode", "source_sha", "api_id",
    "user_pool_id", "client_id", "invitation_jwks_sha256", "mapit_jwks_sha256",
    "authorization_table_arn", "binding_table_arn", "key_parameter_path", "mapit_config", "tenants",
    "key_publication_start_epoch", "key_publication_end_epoch"})
_CONFIG_FIELDS = frozenset({"region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
    "core_api_url", "geo_api_url", "frontend_url", "discovery_enabled", "http_timeout"})


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class EnrolledDevManifest:
    source_sha: str
    config: MapitConfig = field(repr=False)
    policies: Mapping[str, CognitoDevPolicy] = field(repr=False)
    invitation_keys: Mapping[str, bytes] = field(repr=False)
    mapit_keys: Mapping[str, bytes] = field(repr=False)
    authorization_table_arn: str = field(repr=False)
    binding_table_arn: str = field(repr=False)
    key_parameter_path: str = field(repr=False)
    key_publication_start_epoch: int
    key_publication_end_epoch: int

    def __repr__(self):
        return "EnrolledDevManifest(<redacted>)"


def parse_enrolled_dev_manifest(raw: bytes, invitation_jwks: bytes, mapit_jwks: bytes, *,
                                expected_digest: str, account_id: str) -> EnrolledDevManifest:
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST_BYTES
                or type(expected_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
                or type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or account_id == "0" * 12
                or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_digest)):
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(value) is not dict or set(value) != _FIELDS or type(value["schema"]) is not int
                or value["schema"] != 1 or value["builder"] != "build_dev_enrolled_archive"
                or value["environment"] != "dev" or value["mode"] != "mapit-enrolled"
                or type(value["source_sha"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]) is None
                or value["source_sha"] == "0" * 40):
            raise ValueError
        for key, jwks in (("invitation_jwks_sha256", invitation_jwks), ("mapit_jwks_sha256", mapit_jwks)):
            if (type(jwks) is not bytes or not 0 < len(jwks) <= MAX_JWKS_BYTES
                    or type(value[key]) is not str
                    or value[key] != hashlib.sha256(jwks).hexdigest()):
                raise ValueError
        auth_table = f"arn:aws:dynamodb:eu-west-1:{account_id}:table/honda-mapit-mcp-dev-tenants"
        binding_table = f"arn:aws:dynamodb:eu-west-1:{account_id}:table/honda-mapit-mcp-dev-mapit-identity-bindings"
        key_path = "/honda-mapit-mcp/dev/mapit-identity-binding-config"
        key_start, key_end = value["key_publication_start_epoch"], value["key_publication_end_epoch"]
        if (value["authorization_table_arn"] != auth_table
                or value["binding_table_arn"] != binding_table or value["key_parameter_path"] != key_path
                or type(key_start) is not int or type(key_end) is not int
                or key_start <= 0 or not 0 < key_end - key_start <= 3600
                or type(value["mapit_config"]) is not dict or set(value["mapit_config"]) != _CONFIG_FIELDS):
            raise ValueError
        config = MapitConfig(**value["mapit_config"])
        validate_cloud_config(config)
        if config.frontend_url != "https://app.mapit.me/":
            raise ValueError
        tenants = value["tenants"]
        if type(tenants) is not list or not 1 <= len(tenants) <= 16:
            raise ValueError
        policies, subjects = {}, set()
        for tenant in tenants:
            if (type(tenant) is not dict or set(tenant) != {"key", "subject"}
                    or type(tenant["key"]) is not str
                    or re.fullmatch(r"tenant-[0-9a-f]{64}", tenant["key"]) is None
                    or tenant["key"] in policies or type(tenant["subject"]) is not str
                    or tenant["subject"] in subjects):
                raise ValueError
            policies[tenant["key"]] = CognitoDevPolicy(value["user_pool_id"], value["api_id"],
                value["client_id"], tenant["subject"], request_deadline_seconds=14.0)
            subjects.add(tenant["subject"])
        return EnrolledDevManifest(value["source_sha"], config, MappingProxyType(policies),
            MappingProxyType(parse_cognito_jwks(invitation_jwks)),
            MappingProxyType(parse_cognito_jwks(mapit_jwks)), auth_table, binding_table, key_path, key_start, key_end)
    except Exception:
        raise ValueError("dev_enrolled_manifest_invalid") from None


__all__ = ["EnrolledDevManifest", "parse_enrolled_dev_manifest"]
