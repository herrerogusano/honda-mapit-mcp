"""Offline delivery metadata assembly; not private authority or AWS acceptance.

Callers must load these accepted objects from immutable ACL-private evidence
using their owning parsers. Exact prior-template reconstruction reads the fixed
public repository scaffold through its existing factory. There is no private
file IO, source/CI check, credential discovery, key/session loading or write.
The future operator must
create a fresh private envelope and independently verify current AWS state.
"""
from __future__ import annotations

import hashlib
import re

from scripts.dev_owner_enrolled_inputs import build_owner_manifest
from scripts.dev_owner_enrolled_delivery import (
    SERVICE_ROLE_NAME, _validate_authority, _validate_accepted,
    _template_sha, _digest,
)
from scripts.dev_owner_enrolled_runtime import _rebuild_prior
from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS
from scripts.run_dev_mapit_binding_key_setup import _parse_accepted_bootstrap_state
from scripts.run_dev_owner_invitation import _parser_only_clients
from scripts.dev_identity_binding_runtime_evidence import _resolve_context


def assemble_delivery_metadata(*, manifest_inputs, prior_template, runtime_binding,
                               run_id, ci_run_id, start, end,
                               execution_start, execution_end):
    """Build exact closed-delivery metadata from already trusted evidence.

    Receipt digests use the owning bootstrap binding convention; invitation
    and publication use canonical validated direct-journal state. Owner OAuth
    uses the registered context's original accepted candidate readback digest.
    No historical authority is renewed: run/window/source describe a new,
    separate delivery only, whose private publication is not performed here.
    ``runtime_binding`` remains an explicit caller-trusted metadata boundary,
    not a registered accepted-parser capability. Available prior fingerprints
    are cross-checked here; its private journal/physical pool/client provenance
    must still be established by the owning loader and fresh runtime verifier.
    """
    try:
        if type(manifest_inputs) is not dict or type(runtime_binding) is not dict:
            raise ValueError
        raw = build_owner_manifest(**manifest_inputs)
        context = manifest_inputs["context"]
        bootstrap = manifest_inputs["bootstrap_authority"]
        bootstrap_state = manifest_inputs["bootstrap_state"]
        prior, old_keys, bucket, api, account = _rebuild_prior(prior_template)
        storage_keys = runtime_binding.get("tenant_keys")
        owner_keys = getattr(bootstrap, "_tenant_keys", None)
        excluded_keys = getattr(bootstrap, "_excluded_tenant_keys", None)
        if (set(runtime_binding) != _BINDING_FIELDS
                or account != context.account or api != context.policy.api_id
                or runtime_binding["account_id"] != account
                or runtime_binding["operator_user_arn"] != context.operator
                or runtime_binding["api_id"] != api
                or runtime_binding["template_sha256"] != _template_sha(prior)
                or type(storage_keys) not in (tuple, list) or len(storage_keys) != 2
                or any(type(key) is not str or re.fullmatch(r"tenant-[0-9a-f]{64}", key) is None for key in storage_keys)
                or not _valid_namespace_key_separation(
                    owner_keys=owner_keys, storage_keys=storage_keys,
                    hosted_keys=old_keys, excluded_keys=excluded_keys)
                or type(runtime_binding["app_run_id"]) is not int or runtime_binding["app_run_id"] <= 0
                or type(runtime_binding["user_pool_id"]) is not str
                or re.fullmatch(r"eu-west-1_[A-Za-z0-9]{9,45}", runtime_binding["user_pool_id"]) is None
                or type(runtime_binding["client_id"]) is not str
                or re.fullmatch(r"[A-Za-z0-9]{8,128}", runtime_binding["client_id"]) is None
                or runtime_binding["ssm_key_arn"] != bootstrap.ssm_key_arn
                or runtime_binding["github_owner_id"] != context.github_owner_id
                or runtime_binding["github_repository_id"] != context.github_repository_id
                or runtime_binding["handler_role_arn"] != (
                    f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-handler-role")):
            raise ValueError
        physical = {name: {"PhysicalResourceId": runtime_binding[field]} for name, field in (
            ("McpApi", "api_id"), ("McpUserPool", "user_pool_id"), ("McpUserPoolClient", "client_id"))}
        role = prior["Resources"]["McpHandlerRole"]["Properties"]
        policies = {row["PolicyName"]: _resolve_context(row["PolicyDocument"],
                    account=account, resource_rows=physical) for row in role["Policies"]}
        if (runtime_binding["handler_trust_sha256"] != _digest(role["AssumeRolePolicyDocument"])
                or runtime_binding["handler_policies_sha256"] != _digest(policies)):
            raise ValueError
        stack = runtime_binding["app_stack_arn"]
        zip_sha = prior["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"][8:-4]
        if runtime_binding["code_sha256"] != zip_sha:
            raise ValueError
        class Journal:
            def load(self): return bootstrap_state
            def save(self, _value): raise ValueError
            def locked(self): raise ValueError
        _, _, bootstrap_receipt = _parse_accepted_bootstrap_state(
            bootstrap, Journal(), _parser_only_clients())
        invitation = manifest_inputs["invitation"]
        publication = manifest_inputs["publication"]
        owner_key = bootstrap._tenant_keys[0]
        table_id = bootstrap_state["readback_receipt"]["table_id"]
        value = {
            "schema": 1, "kind": "dev-owner-enrolled-delivery", "account_id": account,
            "operator_arn": context.operator, "source_sha": manifest_inputs["source_sha"],
            "ci_run_id": ci_run_id, "run_id": run_id,
            "authorized_from_epoch": start, "authorized_until_epoch": end,
            "stack_id": stack, "service_role_arn": f"arn:aws:iam::{account}:role/{SERVICE_ROLE_NAME}",
            "artifact_bucket": bucket, "owner_context_sha256": context.context_digest,
            "owner_pool_id": context.policy.user_pool_id, "owner_client_id": context.policy.client_id,
            "owner_resource_uri": context.policy.resource_url,
            "owner_oauth_receipt_sha256": context.readback_digest,
            "mapit_bootstrap_authority_sha256": bootstrap._binding_sha256,
            "mapit_bootstrap_receipt_sha256": bootstrap_receipt, "mapit_table_id": table_id,
            "invitation_receipt_sha256": _digest(invitation),
            "key_publication_receipt_sha256": _digest(publication),
            "owner_tenant_key": owner_key, "mapit_config_path": publication["parameter_path"],
            "mapit_config_version": 1, "runtime_evidence_sha256": bootstrap.runtime_evidence_sha256,
            "historical_tenant_keys": list(old_keys), "github_owner_id": context.github_owner_id,
            "github_repository_id": context.github_repository_id,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "invitation_jwks_sha256": hashlib.sha256(manifest_inputs["invitation_jwks"]).hexdigest(),
            "mapit_jwks_sha256": hashlib.sha256(manifest_inputs["mapit_jwks"]).hexdigest(),
            "prior_template_sha256": _template_sha(prior), "prior_zip_sha256": zip_sha,
            "execution_start_epoch": execution_start, "execution_end_epoch": execution_end,
        }
        authority = _validate_authority(value)
        accepted = {
            "owner_oauth": {"status": "accepted", "receipt_sha256": context.readback_digest,
                "account_id": account, "pool_id": context.policy.user_pool_id,
                "client_id": context.policy.client_id, "resource_uri": context.policy.resource_url,
                "scope": context.policy.required_scope},
            "mapit_bootstrap": {"status": "accepted", "receipt_sha256": bootstrap_receipt,
                "authority_sha256": bootstrap._binding_sha256, "account_id": account,
                "tenant_key": owner_key, "table_id": table_id},
            "invitation": {"status": "accepted", "receipt_sha256": _digest(invitation),
                "account_id": account, "table_name": "honda-mapit-mcp-dev-tenants",
                "tenant_key": owner_key, "revision": 1},
            "key_publication": {"status": "accepted", "receipt_sha256": _digest(publication),
                "account_id": account, "parameter_path": publication["parameter_path"], "version": 1},
        }
        _validate_accepted(accepted, authority)
        return {"authority": authority, "accepted": accepted, "manifest_raw": raw}
    except Exception:
        raise ValueError("owner_delivery_metadata_unverified") from None


def _valid_namespace_key_separation(*, owner_keys, storage_keys, hosted_keys, excluded_keys):
    """Keep bootstrap-owned storage exclusions distinct from hosted A/B keys.

    The accepted bootstrap excludes its storage namespace pair; the prior
    hosted manifest independently identifies the historical hosted pair. The
    new owner key must be fresh across both sets, without rewriting the
    immutable bootstrap authority to include unrelated hosted keys.
    """
    pattern = re.compile(r"tenant-[0-9a-f]{64}")
    groups = (owner_keys, storage_keys, hosted_keys, excluded_keys)
    if any(type(group) not in (tuple, list) for group in groups):
        return False
    if any(any(type(key) is not str or pattern.fullmatch(key) is None for key in group)
           for group in groups):
        return False
    owner, storage, hosted, excluded = map(set, groups)
    return (
        len(owner) == len(owner_keys) and len(owner) > 0
        and len(storage) == len(storage_keys) == 2
        and len(hosted) == len(hosted_keys) == 2
        and len(excluded) == len(excluded_keys)
        and storage.issubset(excluded)
        and not storage.intersection(hosted)
        and not owner.intersection(hosted | storage)
    )
