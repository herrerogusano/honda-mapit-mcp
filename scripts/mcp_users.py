"""Owner CLI to manage invitation-only multiuser accounts.

    python -m scripts.mcp_users --env dev invite friend@example.com [--days 14]
    python -m scripts.mcp_users --env dev list
    python -m scripts.mcp_users --env dev revoke friend@example.com
    python -m scripts.mcp_users --env dev relink friend@example.com

Stack outputs (TableName, UserPoolId, ApiBaseUrl) are read from the
environment's multiuser CloudFormation stack. Invitation tokens are printed
once inside the personal link and only their SHA-256 is stored. ``list``
never shows token material.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import secrets
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from mapit.multiuser_common import (
    INVITE_TTL_SECONDS, MAX_USERS, REGION, STATUS_ACCEPTED, STATUS_ACTIVE, STATUS_INVITED, MultiuserError,
    normalize_email, session_parameter_name, stack_name, validate_environment, validate_tenant_id,
)

MAX_INVITE_DAYS = 60
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class UsersError(RuntimeError):
    """Operator-facing failure without secrets."""


@dataclass
class Clients:
    cloudformation: Any
    dynamodb: Any
    cognito: Any
    ssm: Any


@dataclass(frozen=True)
class StackOutputs:
    table: str
    user_pool_id: str
    api_base_url: str


def _code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def read_outputs(cloudformation: Any, env: str) -> StackOutputs:
    stacks = cloudformation.describe_stacks(StackName=stack_name(env))["Stacks"]
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stacks[0].get("Outputs", [])}
    try:
        return StackOutputs(outputs["TableName"], outputs["UserPoolId"], outputs["ApiBaseUrl"].rstrip("/"))
    except KeyError:
        raise UsersError("stack outputs incomplete") from None


def _scan(dynamodb: Any, table: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    start = None
    while True:
        request = {"TableName": table, "ConsistentRead": True, **kwargs}
        if start:
            request["ExclusiveStartKey"] = start
        page = dynamodb.scan(**request)
        items.extend(page.get("Items", []))
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


def _count(dynamodb: Any, table: str) -> int:
    total = 0
    start = None
    while True:
        request = {"TableName": table, "Select": "COUNT", "ConsistentRead": True}
        if start:
            request["ExclusiveStartKey"] = start
        page = dynamodb.scan(**request)
        total += int(page.get("Count", 0))
        start = page.get("LastEvaluatedKey")
        if not start:
            return total


def _iso(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def _number(item: dict[str, Any], name: str) -> Any:
    value = item.get(name)
    return value.get("N") if isinstance(value, dict) else None


def _string(item: dict[str, Any], name: str) -> str | None:
    value = item.get(name)
    return value.get("S") if isinstance(value, dict) else None


class UserAdmin:
    def __init__(self, env: str, clients: Clients, *, out: Callable[[str], None] = print,
                 clock: Callable[[], float] = time.time,
                 token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
                 tenant_factory: Callable[[], str] = lambda: uuid.uuid4().hex) -> None:
        self.env = validate_environment(env)
        self.clients = clients
        self.out = out
        self.clock = clock
        self.token_factory = token_factory
        self.tenant_factory = tenant_factory
        self._outputs: StackOutputs | None = None

    @property
    def outputs(self) -> StackOutputs:
        if self._outputs is None:
            self._outputs = read_outputs(self.clients.cloudformation, self.env)
        return self._outputs

    def invite(self, email: str, days: int = INVITE_TTL_SECONDS // 86400) -> str:
        email = normalize_email(email)
        if type(days) is not int or not 1 <= days <= MAX_INVITE_DAYS:
            raise UsersError(f"--days must be between 1 and {MAX_INVITE_DAYS}")
        table = self.outputs.table
        if _count(self.clients.dynamodb, table) >= MAX_USERS:
            raise UsersError(f"user limit reached ({MAX_USERS}); revoke someone first")
        token = self.token_factory()
        if type(token) is not str or not TOKEN_RE.fullmatch(token):
            raise UsersError("generated invitation token invalid")
        tenant_id = validate_tenant_id(self.tenant_factory())
        now = int(self.clock())
        expires = now + days * 86400
        try:
            self.clients.dynamodb.put_item(
                TableName=table,
                Item={
                    "email": {"S": email},
                    "tenant_id": {"S": tenant_id},
                    "status": {"S": STATUS_INVITED},
                    "invite_token_sha256": {"S": hashlib.sha256(token.encode("ascii")).hexdigest()},
                    "invite_expires_at": {"N": str(expires)},
                    "failed_logins": {"N": "0"},
                    "created_at": {"N": str(now)},
                    "updated_at": {"N": str(now)},
                },
                ConditionExpression="attribute_not_exists(email)",
            )
        except Exception as error:
            if _code(error) == "ConditionalCheckFailedException":
                raise UsersError("this email already has an invitation; use revoke or relink") from None
            raise
        link = f"{self.outputs.api_base_url}/invitacion?{urlencode({'email': email, 'token': token})}"
        self.out(f"Invitation for {email} (expires {_iso(expires)}):")
        self.out(link)
        return link

    def list(self) -> list[dict[str, str]]:
        items = _scan(self.clients.dynamodb, self.outputs.table,
                      ProjectionExpression="email, #s, created_at, last_login_at, invite_expires_at",
                      ExpressionAttributeNames={"#s": "status"})
        rows = sorted(({
            "email": _string(item, "email") or "-",
            "status": _string(item, "status") or "-",
            "created": _iso(_number(item, "created_at")),
            "last_login": _iso(_number(item, "last_login_at")),
        } for item in items), key=lambda row: row["email"])
        self.out(f"{'email':<40} {'status':<9} {'created':<21} last_login")
        for row in rows:
            self.out(f"{row['email']:<40} {row['status']:<9} {row['created']:<21} {row['last_login']}")
        self.out(f"{len(rows)}/{MAX_USERS} users")
        return rows

    def _item(self, email: str) -> dict[str, Any] | None:
        response = self.clients.dynamodb.get_item(
            TableName=self.outputs.table, Key={"email": {"S": email}}, ConsistentRead=True)
        return response.get("Item")

    def _delete_user(self, email: str) -> None:
        try:
            self.clients.cognito.admin_delete_user(UserPoolId=self.outputs.user_pool_id, Username=email)
            self.out("Cognito user deleted")
        except Exception as error:
            if _code(error) != "UserNotFoundException":
                raise
            self.out("Cognito user not present")

    def _delete_session(self, item: dict[str, Any] | None) -> None:
        tenant = _string(item or {}, "tenant_id")
        if tenant is None:
            self.out("No tenant id; no session parameter to delete")
            return
        try:
            name = session_parameter_name(self.env, tenant)
        except MultiuserError:
            raise UsersError("stored tenant id is malformed") from None
        try:
            self.clients.ssm.delete_parameter(Name=name)
            self.out("MAPIT session parameter deleted")
        except Exception as error:
            if _code(error) != "ParameterNotFound":
                raise
            self.out("MAPIT session parameter not present")

    def revoke(self, email: str) -> None:
        email = normalize_email(email)
        item = self._item(email)
        self._delete_user(email)
        self._delete_session(item)
        if item is None:
            self.out("No invitation item")
            return
        self.clients.dynamodb.delete_item(TableName=self.outputs.table, Key={"email": {"S": email}})
        self.out(f"Revoked {email}")

    def relink(self, email: str) -> None:
        email = normalize_email(email)
        item = self._item(email)
        if item is None:
            raise UsersError("no invitation for this email")
        if _string(item, "status") not in (STATUS_ACCEPTED, STATUS_ACTIVE):
            # An invited user has not consented yet; relink must not skip consent.
            raise UsersError("invitation not accepted yet; nothing to relink")
        self._delete_user(email)
        self._delete_session(item)
        self.clients.dynamodb.update_item(
            TableName=self.outputs.table, Key={"email": {"S": email}},
            UpdateExpression="SET #s = :accepted, updated_at = :now, failed_logins = :zero REMOVE locked_until",
            ConditionExpression="attribute_exists(email) AND #s IN (:accepted, :active)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":accepted": {"S": STATUS_ACCEPTED}, ":active": {"S": STATUS_ACTIVE},
                                       ":now": {"N": str(int(self.clock()))}, ":zero": {"N": "0"}},
        )
        self.out(f"{email} must sign in again with the current MAPIT password")


def default_clients() -> Clients:  # pragma: no cover - real AWS only
    import boto3

    session = boto3.session.Session(region_name=REGION)
    return Clients(cloudformation=session.client("cloudformation"), dynamodb=session.client("dynamodb"),
                   cognito=session.client("cognito-idp"), ssm=session.client("ssm"))


def main(argv: list[str] | None = None, *, clients: Clients | None = None,
         out: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(description="Manage invitation-only multiuser MCP accounts.")
    parser.add_argument("--env", required=True, choices=["dev", "prod"])
    commands = parser.add_subparsers(dest="command", required=True)
    invite = commands.add_parser("invite")
    invite.add_argument("email")
    invite.add_argument("--days", type=int, default=INVITE_TTL_SECONDS // 86400)
    commands.add_parser("list")
    for name in ("revoke", "relink"):
        commands.add_parser(name).add_argument("email")
    args = parser.parse_args(argv)
    admin = UserAdmin(args.env, clients or default_clients(), out=out)
    try:
        if args.command == "invite":
            admin.invite(args.email, args.days)
        elif args.command == "list":
            admin.list()
        elif args.command == "revoke":
            admin.revoke(args.email)
        else:
            admin.relink(args.email)
    except (UsersError, MultiuserError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
