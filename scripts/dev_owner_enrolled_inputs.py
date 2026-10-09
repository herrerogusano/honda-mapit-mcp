"""Pure owner manifest assembly from explicitly supplied accepted evidence.

No filesystem, SDK, JWKS fetch, session/key loading or authority creation occurs
here. The future operator must load immutable ACL-private receipts with their
owning parsers and independently verify current AWS state before deployment.
"""
from __future__ import annotations

import hashlib
import json
import re

from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from scripts import dev_owner_login_context as owner_login
from scripts.dev_mapit_bootstrap_contract import MapitBootstrapAuthority
from scripts.run_dev_mapit_binding_key_setup import _CONFIG_FIELDS, _digest, _parse_accepted_bootstrap_state
from scripts.run_dev_owner_invitation import KIND, _validate_authority_metadata, _parser_only_clients


def build_owner_manifest(*, context, bootstrap_authority, bootstrap_state,
                         publication, invitation_authority, invitation, public_config,
                         source_sha, invitation_jwks, mapit_jwks):
    """Bind one bootstrap-authorized owner and accepted publication window.

    The result is deployment metadata, not current-cloud or business acceptance.
    Public config must be the exact retained publication input selected by the
    private preparer; no credential or session fields are accepted.
    """
    try:
        if (type(context) is not owner_login.AcceptedOwnerLoginContext
                or owner_login._ACCEPTED.get(id(context)) is not context
                or type(bootstrap_authority) is not MapitBootstrapAuthority
                or bootstrap_authority.account_id != context.account
                or bootstrap_authority.expected_caller_arn != context.operator
                or len(bootstrap_authority._tenant_keys) != 1
                or type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
                or source_sha == "0" * 40
                or type(public_config) is not dict or set(public_config) != _CONFIG_FIELDS
                or type(public_config["discovery_enabled"]) is not bool
                or type(public_config["http_timeout"]) not in (int, float)
                or any(type(public_config[name]) is not str
                       for name in _CONFIG_FIELDS - {"discovery_enabled", "http_timeout"})):
            raise ValueError
        key = bootstrap_authority._tenant_keys[0]
        class EvidenceJournal:
            def load(self):
                return bootstrap_state
            def save(self, _value):
                raise ValueError
            def locked(self):
                raise ValueError
        _, _, bootstrap_receipt = _parse_accepted_bootstrap_state(
            bootstrap_authority, EvidenceJournal(), _parser_only_clients())
        invitation_authority = _validate_authority_metadata(invitation_authority)
        if (invitation_authority["account_id"] != context.account
                or invitation_authority["operator_user_arn"] != context.operator
                or invitation_authority["owner_context_sha256"] != context.context_digest
                or invitation_authority["owner_oauth_stack_id"] != context.stack_id
                or invitation_authority["owner_oauth_client_id"] != context.policy.client_id
                or invitation_authority["github_owner_id"] != context.github_owner_id
                or invitation_authority["github_repository_id"] != context.github_repository_id
                or invitation_authority["owner_tenant_key"] != key
                or invitation_authority["mapit_bootstrap_authority_sha256"] != bootstrap_authority._binding_sha256
                or invitation_authority["mapit_bootstrap_receipt_sha256"] != bootstrap_receipt
                or invitation_authority["runtime_evidence_sha256"] != bootstrap_authority.runtime_evidence_sha256):
            raise ValueError
        from scripts.dev_owner_enrolled_namespace_readback import _FIELDS
        if (type(publication) is not dict or set(publication) != _FIELDS
                or type(publication["schema"]) is not int or publication["schema"] != 1
                or publication["operation"] != "dev_mapit_binding_key_publication"
                or publication["namespace"] != "mapit" or publication["phase"] != "accepted"
                or publication["account"] != context.account
                or publication["bootstrap_sha256"] != bootstrap_receipt
                or publication["parameter_path"] != "/honda-mapit-mcp/dev/mapit-identity-binding-config"
                or type(publication["run_id"]) is not int or publication["run_id"] <= 0
                or publication["run_id"] == bootstrap_authority.run_id
                or type(publication["source"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", publication["source"]) is None
                or publication["source"] == "0" * 40
                or type(publication["start"]) is not int or type(publication["end"]) is not int
                or publication["start"] <= 0
                or not 0 < publication["end"] - publication["start"] <= 600):
            raise ValueError
        invitation_fields = {"schema", "kind", "phase", "authority_sha256", "owner_context_sha256",
            "bootstrap_authority_sha256", "bootstrap_receipt_sha256", "runtime_evidence_sha256",
            "source_sha", "run_id", "authorized_from_epoch", "authorized_until_epoch",
            "owner_key", "table_arn", "write_dispatched", "readback_verified"}
        if (type(invitation) is not dict or set(invitation) != invitation_fields
                or invitation.get("phase") != "invitation_accepted"
                or type(invitation.get("schema")) is not int or invitation["schema"] != 1
                or invitation.get("kind") != KIND
                or invitation.get("authority_sha256") != _digest(invitation_authority)
                or invitation.get("source_sha") != invitation_authority["source_sha"]
                or type(invitation.get("run_id")) is not int
                or invitation["run_id"] != invitation_authority["run_id"]
                or any(type(invitation.get(name)) is not int
                       or invitation[name] != invitation_authority[name]
                       for name in ("authorized_from_epoch", "authorized_until_epoch"))
                or invitation.get("owner_context_sha256") != context.context_digest
                or invitation.get("bootstrap_authority_sha256") != bootstrap_authority._binding_sha256
                or invitation.get("bootstrap_receipt_sha256") != bootstrap_receipt
                or invitation.get("runtime_evidence_sha256") != bootstrap_authority.runtime_evidence_sha256
                or invitation.get("owner_key") != key
                or invitation.get("table_arn") != f"arn:aws:dynamodb:eu-west-1:{context.account}:table/honda-mapit-mcp-dev-tenants"
                or invitation.get("write_dispatched") is not True
                or invitation.get("readback_verified") is not True):
            raise ValueError
        value = {"schema": 1, "builder": "build_dev_enrolled_archive", "environment": "dev",
            "mode": "mapit-enrolled", "source_sha": source_sha,
            "api_id": context.policy.api_id, "user_pool_id": context.policy.user_pool_id,
            "client_id": context.policy.client_id,
            "invitation_jwks_sha256": hashlib.sha256(invitation_jwks).hexdigest(),
            "mapit_jwks_sha256": hashlib.sha256(mapit_jwks).hexdigest(),
            "authorization_table_arn": f"arn:aws:dynamodb:eu-west-1:{context.account}:table/honda-mapit-mcp-dev-tenants",
            "binding_table_arn": f"arn:aws:dynamodb:eu-west-1:{context.account}:table/honda-mapit-mcp-dev-mapit-identity-bindings",
            "key_parameter_path": publication["parameter_path"], "mapit_config": public_config,
            "tenants": [{"key": key, "subject": context.policy.owner_subject}],
            "key_publication_start_epoch": publication["start"],
            "key_publication_end_epoch": publication["end"]}
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
        parse_enrolled_dev_manifest(raw, invitation_jwks, mapit_jwks,
            expected_digest=hashlib.sha256(raw).hexdigest(), account_id=context.account)
        return raw
    except Exception:
        raise ValueError("owner_manifest_inputs_unverified") from None
