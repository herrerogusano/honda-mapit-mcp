"""Operator CLI: change-set deploy of the public web stack ``honda-mapit-mcp-{env}-web``.

Two steps:

1. Review: ``python -m scripts.deploy_public_web --env dev --private-config PATH
   --wheel-dir DIR`` verifies the caller identity, reads the bucket of the
   existing multiuser artifacts stack (it never creates or changes that stack),
   builds the shared ZIP (no geography), uploads it if absent and creates a
   change set for the web stack (a stack that does not exist yet is left in
   ``REVIEW_IN_PROGRESS``), printing its changes. It writes nothing in SSM and
   executes nothing.
2. Execute: ``--execute --change-set NAME`` executes exactly that reviewed change
   set, by name. It refuses one that removes or replaces the user pool, its
   login domain, the web client or the table (that loses the users, the login
   address or the counts) unless ``--allow-replacement`` is given. Before
   executing, it creates the fingerprint key if it does not exist
   (``PutParameter`` SecureString, ``Overwrite=False``, value never printed): the
   pass function may only read it and refuses every pass without it. Account
   ids in the printed outputs are masked.

``--store-turnstile-secret`` verifies the caller identity, asks for the
Turnstile secret without echoing it and stores it once (``Overwrite=False``);
nothing else runs. The template never creates that parameter.

The private config is a JSON object with ``domain_prefix`` (web pool login
domain), ``mapit_config`` (object), ``alarm_email``, ``web_callback_url`` (prod
only; dev always uses ``http://localhost:5173/``) and optional
``reserved_concurrency`` (object with any of ``identity``, ``mcp``, ``pass``,
``sweep``: integers 1-999; absent means nothing reserved). ``MapitConfigJson``
and the alarm email are never printed.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mapit.multiuser_common import REGION, artifacts_stack_name, validate_environment
from mapit.public_pass import MAX_SECRET_CHARS, turnstile_secret_parameter_name
from mapit.public_web import FINGERPRINT_KEY_BYTES, fingerprint_key_parameter_name, web_stack_name
from scripts.build_public_web_stack import PROD_CALLBACK_PATTERN, build_public_web_template
from scripts.deploy_multiuser import (
    _DOMAIN, _EMAIL, MAX_CONFIG_BYTES, Clients, DeployError, Deployer, _code, build_zip, mask_account,
    validate_mapit_config,
)

ROLES = ("identity", "mcp", "pass", "sweep")
_RESERVATION_PARAMETER = {"identity": "IdentityReservedConcurrency", "mcp": "McpReservedConcurrency",
                          "pass": "PassReservedConcurrency", "sweep": "SweepReservedConcurrency"}
_SECRET = re.compile(r"^[\x21-\x7e]+$")
_DUMMY_SECRET = re.compile(r"^[0-9]x0+AA$")  # Cloudflare's published test secrets
_CHANGE_SET = re.compile(r"^deploy-[0-9]{14}$")
# Resources whose replacement or removal loses users, the login address or the counts.
PROTECTED_RESOURCES = frozenset({"UserPool", "UserPoolDomain", "WebStateTable", "WebClient"})


@dataclass(frozen=True)
class WebConfig:
    domain_prefix: str
    mapit_config_json: str
    alarm_email: str
    web_callback_url: str | None
    reserved_concurrency: tuple[tuple[str, int], ...] = ()

    def __repr__(self) -> str:  # never leak private values
        return "WebConfig(<redacted>)"


@dataclass
class WebClients:
    sts: Any
    cloudformation: Any
    s3: Any
    ssm: Any


def load_web_config(path: Path, env: str) -> WebConfig:
    env = validate_environment(env)
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise DeployError("private config unreadable") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise DeployError("private config too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise DeployError("private config is not valid JSON") from None
    required = {"domain_prefix", "mapit_config", "alarm_email"} | ({"web_callback_url"} if env == "prod" else set())
    allowed = required | {"reserved_concurrency"}
    if not isinstance(value, dict) or not required <= set(value) or not set(value) <= allowed:
        raise DeployError("private config fields invalid")
    domain = value["domain_prefix"]
    if type(domain) is not str or not _DOMAIN.fullmatch(domain) or any(w in domain for w in ("aws", "amazon", "cognito")):
        raise DeployError("domain_prefix invalid")
    mapit_json = validate_mapit_config(value["mapit_config"])
    email = value["alarm_email"]
    if type(email) is not str or not _EMAIL.fullmatch(email) or len(email) > 254:
        raise DeployError("alarm_email invalid")
    callback = value.get("web_callback_url")
    if env == "prod" and (type(callback) is not str or not re.fullmatch(PROD_CALLBACK_PATTERN, callback)):
        raise DeployError("web_callback_url invalid (exact https URL, no port, query or fragment)")
    reservations = value.get("reserved_concurrency", {})
    if not isinstance(reservations, dict) or not set(reservations) <= set(ROLES) or any(
            type(item) is not int or not 1 <= item <= 999 for item in reservations.values()):
        raise DeployError("reserved_concurrency invalid (identity, mcp, pass, sweep: integers 1-999)")
    return WebConfig(domain, mapit_json, email, callback,
                     tuple((role, reservations[role]) for role in ROLES if role in reservations))


def stack_parameters(env: str, config: WebConfig, artifact_key: str) -> list[dict[str, str]]:
    params = {
        "ArtifactKey": artifact_key,
        "DomainPrefix": config.domain_prefix,
        "MapitConfigJson": config.mapit_config_json,
        "AlarmEmail": config.alarm_email,
    }
    if validate_environment(env) == "prod":
        params["WebCallbackUrl"] = str(config.web_callback_url)
    reserved = dict(config.reserved_concurrency)
    for role in ROLES:
        params[_RESERVATION_PARAMETER[role]] = str(reserved[role]) if role in reserved else ""
    return [{"ParameterKey": key, "ParameterValue": value} for key, value in params.items()]


def parameter_exists(ssm: Any, name: str) -> bool:
    """Metadata only (``DescribeParameters``): the value is never read."""
    response = ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}])
    found = [item for item in response.get("Parameters", []) if item.get("Name") == name]
    if found and found[0].get("Type") != "SecureString":
        raise DeployError(f"{name} exists but is not a SecureString")
    return bool(found)


def new_fingerprint_key(token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> str:
    key = token_bytes(FINGERPRINT_KEY_BYTES)
    if type(key) is not bytes or len(key) != FINGERPRINT_KEY_BYTES:
        raise DeployError("fingerprint key generation failed")
    return base64.b64encode(key).decode("ascii")


def ensure_fingerprint_key(ssm: Any, env: str, out: Callable[[str], None],
                           token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> bool:
    """Create the key once; True if this call created it. Never overwrites, never prints it."""
    name = fingerprint_key_parameter_name(env)
    try:
        response = ssm.put_parameter(Name=name, Value=new_fingerprint_key(token_bytes), Type="SecureString",
                                     Overwrite=False, Tier="Standard")
    except Exception as error:
        if _code(error) == "ParameterAlreadyExists":
            out(f"Fingerprint key already present: {name}")
            return False
        raise DeployError(f"fingerprint key write failed ({_code(error) or type(error).__name__})") from None
    version = response.get("Version") if isinstance(response, dict) else None
    if type(version) is not int or version < 1:
        raise DeployError("fingerprint key write unconfirmed")
    out(f"Fingerprint key created (value not shown): {name}")
    return True


def store_turnstile_secret(clients: WebClients, env: str, ask: Callable[[str], str] = getpass.getpass,
                           out: Callable[[str], None] = print) -> None:
    env = validate_environment(env)
    # Same caller checks as a deployment (no root, masked account) before asking for anything.
    Deployer(env, Clients(clients.sts, None, None), out=out).verify_identity()
    ssm = clients.ssm
    name = turnstile_secret_parameter_name(env)
    secret = ask("Turnstile secret (not shown): ")
    if type(secret) is not str or not 1 <= len(secret) <= MAX_SECRET_CHARS or not _SECRET.fullmatch(secret):
        raise DeployError("Turnstile secret invalid (printable ASCII, no spaces)")
    if validate_environment(env) == "prod" and _DUMMY_SECRET.fullmatch(secret):
        raise DeployError("Turnstile test secrets are refused in prod")
    try:
        ssm.put_parameter(Name=name, Value=secret, Type="SecureString", Overwrite=False, Tier="Standard")
    except Exception as error:
        if _code(error) == "ParameterAlreadyExists":
            raise DeployError(f"{name} already exists; this command never overwrites it") from None
        raise DeployError(f"Turnstile secret write failed ({_code(error) or type(error).__name__})") from None
    out(f"Turnstile secret stored (value not shown): {name}")


def protected_changes(changes: list[dict[str, Any]]) -> list[str]:
    """Logical ids of protected resources that the change set would remove or replace."""
    found = []
    for change in changes:
        item = change.get("ResourceChange", {}) if isinstance(change, dict) else {}
        if item.get("LogicalResourceId") in PROTECTED_RESOURCES and (
                item.get("Action") == "Remove" or item.get("Replacement") in ("True", "Conditional")):
            found.append(str(item["LogicalResourceId"]))
    return sorted(set(found))


def run(env: str, config: WebConfig, clients: WebClients, *,
        build: Callable[[Path], tuple[Path, str]], out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep, workdir: Path | None = None,
        change_set_suffix: Callable[[], str] | None = None) -> int:
    """Review step: uploads the ZIP if absent and creates the change set; no SSM write, no execution."""
    env = validate_environment(env)
    deployer = Deployer(env, Clients(clients.sts, clients.cloudformation, clients.s3), out=out, sleep=sleep,
                        change_set_suffix=change_set_suffix)
    deployer.verify_identity()

    artifacts = artifacts_stack_name(env)
    if deployer.stack_status(artifacts) not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise DeployError(f"artifacts stack {artifacts} is not ready; deploy it with scripts.deploy_multiuser first")
    bucket = deployer.stack_outputs(artifacts).get("BucketName")
    if not bucket:
        raise DeployError("artifacts stack has no BucketName output")

    key_name = fingerprint_key_parameter_name(env)
    key_present = parameter_exists(clients.ssm, key_name)
    out(f"Fingerprint key {key_name}: {'present' if key_present else 'absent'}")
    secret_name = turnstile_secret_parameter_name(env)
    if parameter_exists(clients.ssm, secret_name):
        out(f"Turnstile secret {secret_name}: present")
    else:
        out(f"Turnstile secret {secret_name}: absent (passes are refused until it is stored). Store it with:")
        out(f"  python -m scripts.deploy_public_web --env {env} --store-turnstile-secret")

    with tempfile.TemporaryDirectory(prefix="mapit-web-") as temporary:
        zip_path, sha256 = build(Path(workdir or temporary))
        artifact_key = f"runtime/{sha256}.zip"
        out(f"Built runtime ZIP sha256={sha256}")
        deployer.upload_if_absent(bucket, artifact_key, zip_path)

    stack = web_stack_name(env)
    result = deployer.create_change_set(stack, build_public_web_template(env),
                                        stack_parameters(env, config, artifact_key))
    if result is None:
        return 0
    change_set, changes = result
    blocked = protected_changes(changes)
    if blocked:
        out("WARNING: this change set removes or replaces " + ", ".join(blocked)
            + "; --execute refuses it unless --allow-replacement is given.")
    if not key_present:
        out("Executing it first creates the fingerprint key (Overwrite=False).")
    out("Not executed. After review, execute exactly this change set with:")
    out(f"  python -m scripts.deploy_public_web --env {env} --execute --change-set {change_set}")
    return 0


def _reviewed_changes(cfn: Any, stack: str, change_set: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs = {"StackName": stack, "ChangeSetName": change_set}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_change_set(**kwargs)
        if page.get("Status") != "CREATE_COMPLETE" or page.get("ExecutionStatus") != "AVAILABLE":
            raise DeployError(f"change set {change_set} is not ready to execute "
                              f"({page.get('Status')}/{page.get('ExecutionStatus')})")
        changes.extend(page.get("Changes", []))
        token = page.get("NextToken")
        if not token:
            return changes


def execute(env: str, clients: WebClients, change_set: str, *, allow_replacement: bool = False,
            out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
            token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> int:
    """Execute a change set created (and reviewed) by an earlier run, by name."""
    env = validate_environment(env)
    if type(change_set) is not str or not _CHANGE_SET.fullmatch(change_set):
        raise DeployError("--change-set must be a name printed by a review run (deploy-YYYYMMDDHHMMSS)")
    deployer = Deployer(env, Clients(clients.sts, clients.cloudformation, clients.s3), out=out, sleep=sleep)
    deployer.verify_identity()
    stack = web_stack_name(env)
    status = deployer.stack_status(stack)
    if status is None or (status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS"):
        raise DeployError(f"stack {stack} cannot take a change set now ({status})")
    changes = _reviewed_changes(clients.cloudformation, stack, change_set)
    deployer.print_changes(stack, change_set, "reviewed", changes)
    blocked = protected_changes(changes)
    if blocked and not allow_replacement:
        raise DeployError("refusing to remove or replace " + ", ".join(blocked)
                          + " (pool, login domain, web client or table); pass --allow-replacement only on purpose")
    # Before the stack exists: the pass can only read the key, and sign-ins need a pass.
    ensure_fingerprint_key(clients.ssm, env, out, token_bytes)
    deployer.execute_change_set(stack, change_set)
    for name, value in sorted(deployer.stack_outputs(stack).items()):
        out(f"  {name}: {_mask_accounts(value)}")
    return 0


def _mask_accounts(value: str) -> str:
    return re.sub(r"(?<![0-9])[0-9]{12}(?![0-9])", lambda match: mask_account(match.group()), str(value))


def default_clients() -> WebClients:  # pragma: no cover - real AWS only
    import boto3

    session = boto3.session.Session(region_name=REGION)
    return WebClients(*(session.client(name, region_name=REGION) for name in ("sts", "cloudformation", "s3", "ssm")))


def main(argv: list[str] | None = None, *, clients: WebClients | None = None,
         build: Callable[[Path], tuple[Path, str]] | None = None,
         ask: Callable[[str], str] = getpass.getpass) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--env", required=True, choices=["dev", "prod"])
    parser.add_argument("--private-config", type=Path, default=None)
    parser.add_argument("--wheel-dir", type=Path, default=None)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--change-set", default=None)
    parser.add_argument("--allow-replacement", action="store_true")
    parser.add_argument("--store-turnstile-secret", action="store_true")
    options = parser.parse_args(argv)
    stage = options.env
    try:
        if options.store_turnstile_secret:
            if (options.private_config or options.execute or options.wheel_dir or options.change_set
                    or options.allow_replacement):
                raise DeployError("--store-turnstile-secret takes only --env")
            store_turnstile_secret(clients or default_clients(), stage, ask)
            return 0
        if options.execute:
            if options.private_config or options.wheel_dir or not options.change_set:
                raise DeployError("--execute takes --change-set (from a review run), not a config or wheels")
            return execute(stage, clients or default_clients(), options.change_set,
                           allow_replacement=options.allow_replacement)
        if options.change_set or options.allow_replacement:
            raise DeployError("--change-set and --allow-replacement only go with --execute")
        if options.private_config is None:
            raise DeployError("--private-config is required")
        config = load_web_config(options.private_config, stage)
        if build is None:
            wheel_dir = options.wheel_dir or (Path(os.environ["HONDA_MAPIT_WHEEL_DIR"])
                                              if os.environ.get("HONDA_MAPIT_WHEEL_DIR") else None)
            if wheel_dir is None:
                raise DeployError("--wheel-dir (or HONDA_MAPIT_WHEEL_DIR) is required")
            build = lambda workdir: build_zip(wheel_dir, None, workdir)  # noqa: E731
        return run(stage, config, clients or default_clients(), build=build)
    except DeployError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["PROTECTED_RESOURCES", "WebClients", "WebConfig", "ensure_fingerprint_key", "execute", "load_web_config",
           "main", "new_fingerprint_key", "parameter_exists", "protected_changes", "run", "stack_parameters",
           "store_turnstile_secret"]
