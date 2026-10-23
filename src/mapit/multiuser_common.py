"""Shared constants and helpers for the invitation-only multiuser stack.

See docs/multiuser-production.md. Pure functions only: no I/O, no SDK.
"""

from __future__ import annotations

import re

REGION = "eu-west-1"
ENVIRONMENTS = ("dev", "prod")
MAX_USERS = 10
CONSENT_VERSION = "2026-10-23"
TENANT_CLAIM = "mapit_tenant"
TENANT_ATTRIBUTE = "custom:tenant_id"
CLAUDE_CALLBACK_URL = "https://claude.ai/api/mcp/auth_callback"

INVITE_TTL_SECONDS = 14 * 24 * 3600
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 15 * 60

STATUS_INVITED = "invited"
STATUS_ACCEPTED = "accepted"
STATUS_ACTIVE = "active"
STATUSES = (STATUS_INVITED, STATUS_ACCEPTED, STATUS_ACTIVE)

TENANT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,190}\.[a-z]{2,24}$")


class MultiuserError(ValueError):
    """Closed validation failure; messages never contain user input."""


def validate_environment(env: str) -> str:
    if env not in ENVIRONMENTS:
        raise MultiuserError("environment_invalid")
    return env


def normalize_email(value: object) -> str:
    """Trim and lowercase; reject anything that is not a plain email address."""
    if type(value) is not str or len(value) > 254:
        raise MultiuserError("email_invalid")
    email = value.strip().lower()
    if not _EMAIL_RE.fullmatch(email) or ".." in email:
        raise MultiuserError("email_invalid")
    return email


def validate_tenant_id(value: object) -> str:
    if type(value) is not str or not TENANT_ID_RE.fullmatch(value):
        raise MultiuserError("tenant_invalid")
    return value


def stack_name(env: str) -> str:
    return f"honda-mapit-mcp-{validate_environment(env)}-multiuser"


def artifacts_stack_name(env: str) -> str:
    return f"honda-mapit-mcp-{validate_environment(env)}-multiuser-artifacts"


def table_name(env: str) -> str:
    return f"honda-mapit-mcp-{validate_environment(env)}-invitations"


def users_parameter_prefix(env: str) -> str:
    return f"/honda-mapit-mcp/{validate_environment(env)}/users/"


def session_parameter_name(env: str, tenant_id: str) -> str:
    return f"{users_parameter_prefix(env)}{validate_tenant_id(tenant_id)}/mapit-refresh-token"


def mcp_url(api_id: str) -> str:
    if type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id):
        raise MultiuserError("api_id_invalid")
    return f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"


__all__ = [name for name in globals() if name.isupper() or name in {
    "MultiuserError", "validate_environment", "normalize_email", "validate_tenant_id",
    "stack_name", "artifacts_stack_name", "table_name", "users_parameter_prefix",
    "session_parameter_name", "mcp_url",
}]
