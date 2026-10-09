"""Static checks of fixed, synthetic CloudFormation drafts; no account operations."""

from __future__ import annotations

import json
import hashlib
import os
import re
import socket
import sys
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from typing import Callable

MAX_TEMPLATE_BYTES = 128 * 1024
CFN_LINT_VERSION = "1.57.1"
_RULE_ID = re.compile(r"[EWI][0-9]{4}\Z")


@contextmanager
def deny_python_network():
    """Deny Python socket/DNS APIs during lint, not a native-code/OS sandbox."""
    names = (
        "socket", "SocketType", "socketpair", "create_connection", "getaddrinfo",
        "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    )
    originals = {name: getattr(socket, name) for name in names if hasattr(socket, name)}

    def denied(*_args, **_kwargs):
        raise RuntimeError("static_lint_network_denied")

    blocked_socket = type("BlockedSocket", (socket.socket,), {"__new__": denied})
    try:
        for name in originals:
            setattr(socket, name, blocked_socket if name in {"socket", "SocketType"} else denied)
        yield
    finally:
        for name, original in originals.items():
            setattr(socket, name, original)


def fixed_documents() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from mapit.aws_dev_cleanup_schedule import build_dev_cleanup_schedule
    from mapit.aws_identity_binding_infra import build_dev_identity_binding_table
    from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
    from scripts.build_aws_dev_mapit_binding_bootstrap import build_dev_mapit_binding_bootstrap
    from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template
    from scripts.build_aws_dev_identity_binding_sse_recovery import templates as dev_binding_sse_templates
    from mapit.aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
    from mapit.aws_dev_oauth_cleanup import build_dev_oauth_cleanup
    from mapit.aws_dev_oauth_cleanup import build_dev_oauth_setup_cleanup
    from mapit.aws_dev_oauth_setup_control_bundle import build_dev_oauth_setup_control_bundle
    from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
    from mapit.aws_dev_control_bundle import build_dev_control_bundle
    from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
    from mapit.aws_shared_identity_dev_cleanup import build_shared_identity_dev_cleanup
    from mapit.aws_dev_shutdown_control import build_dev_shutdown_control
    from mapit.aws_dev_runtime import cognito_dev_policy
    from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template
    from scripts.build_aws_retained_dev import build_retained_dev_template
    from scripts.build_aws_retained_dev_runtime import build_retained_dev_runtime_template
    from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts, build_retained_dev_controls
    from scripts.build_aws_retained_dev_oauth import build_retained_dev_oauth_setup
    from scripts.build_aws_retained_dev_multiuser import (
        build_retained_dev_multiuser_setup, build_retained_dev_multiuser_template,
    )
    from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
    from scripts.build_aws_identity_template import fixed_identity_template
    from scripts.build_aws_shared_identity_dev import build_shared_identity_dev_template
    from scripts.build_aws_dev_oauth_template import build_dev_oauth_setup_template, build_dev_oauth_template
    from scripts.build_aws_dev_runtime_template import (
        fixed_runtime_bucket_template, fixed_runtime_candidate_template,
    )
    from scripts.build_aws_prod_bootstrap import fixed_prod_bootstrap_template
    from scripts.build_aws_prod_controls import fixed_prod_controls_template
    from scripts.build_aws_prod_artifacts import fixed_prod_artifact_template
    from scripts.build_aws_prod_oauth_template import (
        build_prod_oauth_template, build_prod_runtime_template,
    )
    from mapit.aws_prod_runtime import CognitoProdPolicy
    from scripts.build_cd_identity_bootstrap import build_cd_identity_bootstrap
    from scripts.build_cd_delivery_roles import build_cd_delivery_roles
    from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles
    from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
    from scripts.build_cd_retained_dev_proof_role import build_cd_retained_dev_proof_role

    documents = {}
    for label, filename in (
        ("application_draft", "template.json"),
        ("shutdown_lambda_draft", "dev-shutdown.template.json"),
    ):
        source = root / "infra" / "aws" / filename
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TEMPLATE_BYTES:
            raise ValueError("fixed_template_invalid")
        with source.open("rb") as stream:
            raw = stream.read(MAX_TEMPLATE_BYTES + 1)
        if len(raw) > MAX_TEMPLATE_BYTES:
            raise ValueError("fixed_template_invalid")
        documents[label] = raw.decode("utf-8", errors="strict")
    documents["shutdown_control_draft"] = json.dumps(build_dev_shutdown_control(
        AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00",
    ))
    documents["cleanup_schedule_draft"] = json.dumps(build_dev_cleanup_schedule("2030-01-01T00:00:00"))
    documents["combined_control_draft"] = json.dumps(build_dev_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        resource_started_epoch=1893456000,
        now_epoch=1893456060,
        activation_start_epoch=1893456240,
    ))
    documents["closed_bootstrap_draft"] = json.dumps(fixed_bootstrap_template())
    documents["dev_identity_binding_table_draft"] = json.dumps(build_dev_identity_binding_table())
    documents["dev_identity_binding_bootstrap"] = json.dumps(build_dev_identity_binding_bootstrap(
        account_id="123456789012", operator_user_arn="arn:aws:iam::123456789012:user/synthetic-operator",
        tenant_keys=("tenant-" + "c" * 64, "tenant-" + "d" * 64),
        ssm_key_arn="arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"))
    _, sse_owned_target, _, _, _, _ = dev_binding_sse_templates({
        "account_id": "123456789012",
        "operator_user_arn": "arn:aws:iam::123456789012:user/synthetic-operator",
        "tenant_keys": ("tenant-" + "c" * 64, "tenant-" + "d" * 64),
        "ssm_key_arn": "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111",
    })
    documents["dev_identity_binding_sse_owned_target"] = json.dumps(sse_owned_target)
    documents["dev_mapit_identity_binding_bootstrap"] = json.dumps(build_dev_mapit_binding_bootstrap(
        account_id="123456789012", operator_user_arn="arn:aws:iam::123456789012:user/synthetic-operator",
        tenant_keys=("tenant-" + "e" * 64, "tenant-" + "f" * 64),
        excluded_tenant_keys=("tenant-" + "c" * 64, "tenant-" + "d" * 64),
        ssm_key_arn="arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"))
    documents["retained_dev_closed_bootstrap_draft"] = json.dumps(build_retained_dev_template())
    documents["retained_dev_closed_runtime_draft"] = json.dumps(build_retained_dev_runtime_template(
        "123456789012", "a1b2c3d4e5", "a" * 64, "b" * 64,
    ))
    documents["retained_dev_controls_draft"] = json.dumps(build_retained_dev_controls("a1b2c3d4e5"))
    documents["retained_dev_artifacts_draft"] = json.dumps(build_retained_dev_artifacts())
    documents["retained_dev_oauth_draft"] = json.dumps(build_retained_dev_oauth_setup(
        "a1b2c3d4e5", "eu-west-1_AbCdEfGhI", callback_url="http://127.0.0.1:8787/callback",
    ))
    documents["permanent_identity_draft"] = json.dumps(fixed_identity_template())
    documents["dev_owner_oauth_draft"] = json.dumps(build_dev_owner_oauth_template(
        account_id="123456789012", api_id="a1b2c3d4e5",
        owner_pool_id="eu-west-1_AbCdEfGhI", callback_url="http://127.0.0.1:8787/callback",
    ))
    documents["bootstrap_cleanup_draft"] = json.dumps(build_dev_bootstrap_cleanup(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        schedule_at_utc="2030-01-01T00:45:00",
    ))
    documents["bootstrap_control_draft"] = json.dumps(build_dev_bootstrap_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        resource_started_epoch=1893456000,
        now_epoch=1893456060,
        activation_start_epoch=1893456240,
    ))
    documents["runtime_artifact_bucket_draft"] = json.dumps(fixed_runtime_bucket_template())
    documents["runtime_artifact_candidate_draft"] = json.dumps(fixed_runtime_candidate_template(
        "honda-mapit-mcp-dev-synthetic-artifact", "a" * 64,
    ))
    documents["closed_oauth_setup_draft"] = json.dumps(build_dev_oauth_setup_template(
        "a1b2c3d4e5", callback_url="http://localhost:39031/callback/synthetic",
    ))
    documents["closed_oauth_runtime_draft"] = json.dumps(build_dev_oauth_template(
        cognito_dev_policy(
            user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
            client_id="syntheticclient123",
            owner_subject="12345678-1234-4234-8234-123456789abc",
        ),
        bucket="honda-mapit-mcp-dev-synthetic-artifact", zip_sha256="a" * 64,
        jwks_sha256="b" * 64, callback_url="http://localhost:39031/callback/synthetic",
        execution_start=1893456000, execution_end=1893456300,
    ))
    shared_policy = cognito_dev_policy(
        user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
        client_id="syntheticclient123",
        owner_subject="12345678-1234-4234-8234-123456789abc",
    )
    documents["shared_identity_dev_runtime_draft"] = json.dumps(build_shared_identity_dev_template(
        shared_policy,
        bucket="honda-mapit-mcp-dev-synthetic-artifact", zip_sha256="a" * 64,
        jwks_sha256="b" * 64, callback_url="http://localhost:39031/callback/synthetic",
        execution_start=1893456000, execution_end=1893456300,
    ))
    documents["closed_oauth_cleanup_draft"] = json.dumps(build_dev_oauth_cleanup(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        schedule_at_utc="2030-01-01T00:45:00",
        authorizer_id="auth123", integration_id="int123",
        post_route_id="post123", metadata_route_id="meta123",
    ))
    documents["shared_identity_dev_cleanup_draft"] = json.dumps(build_shared_identity_dev_cleanup(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        schedule_at_utc="2030-01-01T00:45:00",
        authorizer_id="auth123", integration_id="int123",
        post_route_id="post123", metadata_route_id="meta123",
    ))
    documents["closed_oauth_setup_cleanup_draft"] = json.dumps(build_dev_oauth_setup_cleanup(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        schedule_at_utc="2030-01-01T00:45:00",
    ))
    documents["closed_oauth_setup_control_draft"] = json.dumps(build_dev_oauth_setup_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id="eu-west-1_A1b2C3d4E",
        stack_uuid="11111111-2222-3333-4444-555555555555",
        resource_started_epoch=1893456000,
        now_epoch=1893456060,
        activation_start_epoch=1893456240,
    ))
    prod_policy = CognitoProdPolicy(
        user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
        client_id="ProdClientSynthetic123",
        owner_subject="12345678-1234-4234-8234-123456789abc",
    )
    documents["prod_bootstrap_draft"] = json.dumps(fixed_prod_bootstrap_template())
    documents["prod_controls_draft"] = json.dumps(fixed_prod_controls_template("a1b2c3d4e5"))
    documents["prod_artifacts_draft"] = json.dumps(fixed_prod_artifact_template())
    documents["prod_artifacts_cd_retention"] = json.dumps(fixed_prod_artifact_template(journal_retention_days=30))
    documents["prod_oauth_draft"] = json.dumps(build_prod_oauth_template(
        user_pool_id=prod_policy.user_pool_id, api_id=prod_policy.api_id,
        callback_url="http://localhost:8786/mcp/oauth/callback/codex-fixed-server",
    ))
    documents["prod_runtime_draft"] = json.dumps(build_prod_runtime_template(
        prod_policy, bucket="honda-mapit-prod-runtime-artifacts",
        zip_sha256="a" * 64, manifest_sha256="b" * 64,
    ))
    identity_account_id = "123456789012"
    identity_owner_id = "1234567"
    identity_repository_id = "7654321"
    identity_provider_arn = (
        f"arn:aws:iam::{identity_account_id}:oidc-provider/"
        "token.actions.githubusercontent.com"
    )
    for subject_format in ("legacy_environment", "immutable_environment"):
        observed_subjects = {}
        for target in ("dev", "prod"):
            if subject_format == "legacy_environment":
                subject = f"repo:herrerogusano/honda-mapit-mcp:environment:{target}"
            else:
                subject = (
                    f"repo:herrerogusano@{identity_owner_id}/"
                    f"honda-mapit-mcp@{identity_repository_id}:environment:{target}"
                )
            observed_subjects[target] = {
                "format": subject_format,
                "sha256": hashlib.sha256(subject.encode("ascii")).hexdigest(),
            }
        label = "cd_identity_legacy_draft" if subject_format == "legacy_environment" else "cd_identity_immutable_draft"
        documents[label] = json.dumps(build_cd_identity_bootstrap(
            account_id=identity_account_id,
            provider_arn=identity_provider_arn,
            owner_id=identity_owner_id,
            repository_id=identity_repository_id,
            observed_subjects=observed_subjects,
        ))
        delivery_label = (
            "cd_delivery_legacy_draft" if subject_format == "legacy_environment"
            else "cd_delivery_immutable_draft"
        )
        delivery_arguments = dict(
            account_id=identity_account_id,
            provider_arn=identity_provider_arn,
            owner_id=identity_owner_id,
            repository_id=identity_repository_id,
            observed_prod_subject_format=subject_format,
            observed_prod_subject_sha256=observed_subjects["prod"]["sha256"],
            stack_arn=(f"arn:aws:cloudformation:eu-west-1:{identity_account_id}:stack/"
                       "honda-mapit-mcp-prod/11111111-2222-4333-8444-555555555555"),
            handler_arn=(f"arn:aws:lambda:eu-west-1:{identity_account_id}:function:"
                         "honda-mapit-mcp-prod-handler"),
            api_arn="arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
            shutdown_state_machine_arn=(f"arn:aws:states:eu-west-1:{identity_account_id}:stateMachine:"
                                        "honda-mapit-mcp-prod-shutdown"),
            artifact_bucket_arn=("arn:aws:s3:::honda-mapit-mcp-prod-runtime-artifacts-"
                                 "syntheticbucket1"),
            execution_role_arn=f"arn:aws:iam::{identity_account_id}:role/honda-mapit-mcp-prod-runtime",
            tripwire_alarm_arn=(f"arn:aws:cloudwatch:eu-west-1:{identity_account_id}:alarm:"
                                "honda-mapit-mcp-prod-request-tripwire"),
            tripwire_rule_arn=(f"arn:aws:events:eu-west-1:{identity_account_id}:rule/"
                               "honda-mapit-mcp-prod-request-tripwire-alarm-rule"),
            allow_execution_role_passrole=True,
        )
        documents[delivery_label] = json.dumps(build_cd_delivery_roles(**delivery_arguments))
        if subject_format == "immutable_environment":
            documents["cd_delivery_lambda_key_draft"] = json.dumps(build_cd_delivery_roles(
                **delivery_arguments,
                lambda_environment_key_arn=(f"arn:aws:kms:eu-west-1:{identity_account_id}:key/"
                                            "11111111-2222-4333-8444-555555555555"),
            ))
    retained_stack = (f"arn:aws:cloudformation:eu-west-1:{identity_account_id}:stack/"
                      "honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555")
    retained_artifact_stack = (f"arn:aws:cloudformation:eu-west-1:{identity_account_id}:stack/"
                               "honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666")
    retained_base = dict(
        account_id=identity_account_id, provider_arn=identity_provider_arn,
        owner_id=identity_owner_id, repository_id=identity_repository_id,
        stack_arn=retained_stack, artifact_stack_arn=retained_artifact_stack,
        handler_arn=(f"arn:aws:lambda:eu-west-1:{identity_account_id}:function:"
                     "honda-mapit-mcp-dev-retained-handler"),
        api_arn="arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
        shutdown_state_machine_arn=(f"arn:aws:states:eu-west-1:{identity_account_id}:stateMachine:"
                                    "honda-mapit-mcp-dev-retained-shutdown"),
        artifact_bucket_arn=(f"arn:aws:s3:::honda-mapit-mcp-dev-retained-"
                             f"{identity_account_id}-eu-west-1"),
        execution_role_arn=(f"arn:aws:iam::{identity_account_id}:role/"
                            "honda-mapit-mcp-dev-retained-handler-role"),
    )
    for subject_format in ("legacy_environment", "immutable_environment"):
        dev_subject = (
            "repo:herrerogusano/honda-mapit-mcp:environment:dev"
            if subject_format == "legacy_environment" else
            f"repo:herrerogusano@{identity_owner_id}/honda-mapit-mcp@{identity_repository_id}:environment:dev"
        )
        retained_args = dict(retained_base,
                             observed_dev_subject_format=subject_format,
                             observed_dev_subject_sha256=hashlib.sha256(dev_subject.encode("ascii")).hexdigest())
        label = "cd_retained_dev_legacy_draft" if subject_format == "legacy_environment" else "cd_retained_dev_immutable_draft"
        documents[label] = json.dumps(build_cd_retained_dev_roles(**retained_args))
        if subject_format == "immutable_environment":
            documents["cd_retained_dev_lambda_key_draft"] = json.dumps(build_cd_retained_dev_roles(
                **retained_args,
                lambda_environment_key_arn=(f"arn:aws:kms:eu-west-1:{identity_account_id}:key/"
                                            "11111111-2222-4333-8444-555555555555"),
            ))
    documents["cd_retained_dev_readonly_proof_draft"] = json.dumps(build_cd_retained_dev_proof_role(
        account_id=identity_account_id, provider_arn=identity_provider_arn,
        owner_id=identity_owner_id, repository_id=identity_repository_id,
        observed_dev_subject_sha256=hashlib.sha256(dev_subject.encode("ascii")).hexdigest(),
        app_stack_arn=retained_stack, artifact_stack_arn=retained_artifact_stack,
        controls_stack_arn=(f"arn:aws:cloudformation:eu-west-1:{identity_account_id}:stack/"
                            "honda-mapit-mcp-dev-retained-controls/33333333-4444-4555-8666-777777777777"),
        artifact_bucket_arn=retained_base["artifact_bucket_arn"],
        api_arn=retained_base["api_arn"], handler_arn=retained_base["handler_arn"],
        cfn_role_arn=f"arn:aws:iam::{identity_account_id}:role/honda-mapit-mcp-dev-retained-cfn-update",
        execution_role_arn=retained_base["execution_role_arn"],
        cfn_boundary_arn=f"arn:aws:iam::{identity_account_id}:policy/honda-mapit-mcp-dev-retained-cfn-update-boundary",
        executor_boundary_arn=f"arn:aws:iam::{identity_account_id}:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary",
        shutdown_state_machine_arn=retained_base["shutdown_state_machine_arn"],
        tripwire_alarm_arn=f"arn:aws:cloudwatch:eu-west-1:{identity_account_id}:alarm:honda-mapit-mcp-dev-retained-request-tripwire",
        tripwire_rule_arn=f"arn:aws:events:eu-west-1:{identity_account_id}:rule/honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule",
    ))
    documents["retained_dev_multiuser_timed_controls"] = json.dumps(build_dev_multiuser_timed_controls("a1b2c3d4e5"))
    documents["retained_dev_multiuser_roles_bootstrap"] = json.dumps(build_cd_retained_dev_multiuser_roles(**retained_args))
    documents["retained_dev_multiuser_roles_recurrent_existing_key"] = json.dumps(build_cd_retained_dev_multiuser_roles(
        **retained_args, observed_user_pool_id="eu-west-1_A1b2C3d4E",
        lambda_environment_key_arn=f"arn:aws:kms:eu-west-1:{retained_args['account_id']}:key/11111111-2222-4333-8444-555555555555",
    ))
    documents["retained_dev_multiuser_roles_recurrent"] = json.dumps(build_cd_retained_dev_multiuser_roles(
        **retained_args, observed_user_pool_id="eu-west-1_A1b2C3d4E"))
    documents["retained_dev_multiuser_setup"] = json.dumps(build_retained_dev_multiuser_setup(
        api_id="a1b2c3d4e5", callback_url="http://localhost:39031/callback"))
    documents["retained_dev_multiuser_runtime"] = json.dumps(build_retained_dev_multiuser_template(
        api_id="a1b2c3d4e5", bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        zip_sha256="1" * 64, source_sha256="1" * 40, jwks_sha256="2" * 64,
        manifest_sha256="3" * 64, account_id="123456789012",
        execution_start_epoch=1893456000, execution_end_epoch=1893456300,
        callback_url="http://localhost:39031/callback",
        subjects=("12345678-1234-4234-8234-123456789abc", "22345678-1234-4234-8234-123456789abc"),
        tenant_keys=("tenant-" + "a" * 64, "tenant-" + "b" * 64)))
    return documents


def check_documents(documents: dict[str, str], lint: Callable) -> dict:
    results = []
    for label, document in documents.items():
        matches = lint(document, regions=["eu-west-1"], config={
            "regions": ["eu-west-1"], "config_file": os.devnull,
            "ignore_checks": [], "append_rules": [], "custom_rules": None,
            "ignore_bad_template": False,
        })
        rule_ids = [match.rule.id for match in matches]
        if any(not isinstance(rule, str) or not _RULE_ID.fullmatch(rule) for rule in rule_ids):
            raise ValueError("static_lint_result_invalid")
        failing = any(rule.startswith(("E", "W")) for rule in rule_ids)
        results.append({"component": label, "valid": not failing,
                        "finding_count": len(rule_ids), "rule_ids": sorted(set(rule_ids))})
    return {"success": all(item["valid"] for item in results), "components": results,
            "account_operations": False, "deployment": False}


def main() -> int:
    try:
        with deny_python_network():
            if version("cfn-lint") != CFN_LINT_VERSION:
                raise ValueError("static_lint_version_invalid")
            from cfnlint.api import lint

            result = check_documents(fixed_documents(), lint)
    except Exception:
        print(json.dumps({"success": False, "category": "static_template_check_failed",
                          "account_operations": False, "deployment": False}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
