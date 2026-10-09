"""Load immutable private receipts for the owner-enrolled DEV build.

This is an input loader, not an operator or deployment authority. It performs
no AWS SDK calls and never loads MAPIT keys, refresh tokens, passwords, or
sessions. Its only network operations are two fixed, bounded public Cognito
JWKS GETs. Current cloud state and source/protection gates remain the job of
the separate delivery/readback operator.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import time
import threading
import urllib.request
import weakref
from collections.abc import Mapping
from typing import Any, Callable

from mapit.aws_dev_runtime import parse_cognito_jwks
from mapit.http_transport import open_direct, read_bounded
from scripts.dev_mapit_runtime_evidence import (
    _load_bundle as _load_runtime_bundle,
    _validate_bundle as _validate_runtime_bundle,
    _validate_historical_bootstrap,
    runtime_evidence_digest,
)
from scripts.dev_owner_enrolled_inputs import build_owner_manifest
from scripts.dev_owner_enrolled_runtime import _rebuild_prior
from scripts.dev_owner_enrolled_runtime_readback import _load_accepted_publication
from scripts.dev_owner_login_context import parse_accepted_owner_login_context
from scripts import dev_owner_login_context as _owner_login
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_owner_oauth_bootstrap import _load_binding as _load_owner_binding
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization,
    validate_private_location,
)
from scripts.run_dev_mapit_binding_key_setup import (
    _CONFIG_FIELDS,
    _load_accepted_bootstrap,
    _load_config,
)
from scripts.run_dev_owner_assisted_login import load_trusted_owner_policy
from scripts.run_dev_owner_invitation import (
    _parser_only_clients,
    _read_json as _read_invitation_json,
    _validate_authority as _validate_invitation_authority,
    _validate_authority_metadata,
)

_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_PUBLIC_CONFIG_BYTES = 8 * 1024
_MAX_JWKS_BYTES = 32 * 1024
_JWKS_TOTAL_SECONDS = 10.0
_REGISTERED: weakref.WeakKeyDictionary["OwnerEnrolledPrivateInputs", tuple[Any, ...]] = weakref.WeakKeyDictionary()
_REGISTRY_LOCK = threading.Lock()


class PrivateInputsError(ValueError):
    """Fixed, redacted failure for untrusted or inconsistent private inputs."""

    def __init__(self):
        super().__init__("owner_enrolled_private_inputs_unverified")


def _fail() -> None:
    raise PrivateInputsError()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _snapshot(path: Path, *, maximum: int, acl_checker) -> tuple[Path, bytes, tuple[Any, ...]]:
    """Read a private regular file once and retain a non-sensitive fingerprint."""
    resolved = validate_private_location(Path(path), acl_checker=acl_checker)
    info = resolved.stat()
    if (not stat.S_ISREG(info.st_mode) or type(info.st_size) is not int
            or info.st_size <= 0 or info.st_size > maximum):
        raise ValueError
    raw = resolved.read_bytes()
    if len(raw) != info.st_size or len(raw) > maximum:
        raise ValueError
    fingerprint = (str(resolved), int(info.st_dev), int(info.st_ino), int(info.st_size),
                   int(info.st_mtime_ns), hashlib.sha256(raw).hexdigest())
    return resolved, raw, fingerprint


def _journal_file(state_dir: Path, *, maximum: int, acl_checker) -> tuple[Path, bytes, tuple[Any, ...]]:
    directory = validate_private_location(Path(state_dir), acl_checker=acl_checker)
    if not directory.is_dir():
        raise ValueError
    journal = FileJournal(directory)
    return _snapshot(journal.path, maximum=maximum, acl_checker=acl_checker)


def _read_snapshot_now(fingerprint: tuple[Any, ...], *, maximum: int, acl_checker) -> tuple[Any, ...]:
    path = Path(fingerprint[0])
    _resolved, _raw, current = _snapshot(path, maximum=maximum, acl_checker=acl_checker)
    return current


def _issuer_jwks_url(issuer: str) -> str:
    match = re.fullmatch(r"https://cognito-idp\.eu-west-1\.amazonaws\.com/(eu-west-1_[A-Za-z0-9]{9,64})", issuer)
    if match is None:
        raise ValueError
    return issuer + "/.well-known/jwks.json"


def _fetch_jwks(url: str, *, opener=None, monotonic=time.monotonic) -> bytes:
    """One direct TLS GET, no proxy, redirect, or retry, with a total read bound."""
    if type(url) is not str:
        raise ValueError
    if re.fullmatch(
            r"https://cognito-idp\.eu-west-1\.amazonaws\.com/eu-west-1_[A-Za-z0-9]{9,64}/\.well-known/jwks\.json",
            url) is None:
        raise ValueError
    started = monotonic()
    if type(started) not in (int, float) or isinstance(started, bool) or not math.isfinite(started):
        raise ValueError
    last = started

    def check(_amount: int) -> None:
        nonlocal last
        now = monotonic()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                or now < last or now - started >= _JWKS_TOTAL_SECONDS):
            raise ValueError
        last = now

    request = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-store"},
                                     method="GET")
    response = open_direct(request, timeout=3, opener=opener)
    try:
        status = getattr(response, "status", None)
        if type(status) is not int or status != 200:
            raise ValueError
        raw = read_bounded(response, _MAX_JWKS_BYTES, on_chunk=check)
        check(0)
        if not raw:
            raise ValueError
        parse_cognito_jwks(raw)
        return raw
    finally:
        response.close()


class OwnerEnrolledPrivateInputs:
    """Registered, redacted in-memory projection of accepted private inputs.

    The exposed mappings are mutable for compatibility with the existing pure
    manifest/target builders. ``assert_unchanged`` must be called immediately
    before use; it rejects both mapping mutation and source-file replacement.
    """

    def __init__(self, *, manifest_inputs: dict[str, Any], prior_template: dict[str, Any],
                 runtime_binding: dict[str, Any], bootstrap_template: dict[str, Any],
                 fingerprints: tuple[tuple[Any, ...], ...], max_sizes: Mapping[str, int],
                 acl_checker, object_digest: str):
        self.manifest_inputs = manifest_inputs
        self.prior_template = prior_template
        self.runtime_binding = runtime_binding
        self.bootstrap_template = bootstrap_template
        # Construction alone is not registration. Only the validated loader
        # registers this object after every parser and final file check passes.

    def __repr__(self) -> str:
        return "OwnerEnrolledPrivateInputs(<redacted>)"

    def assert_unchanged(self) -> bool:
        try:
            with _REGISTRY_LOCK:
                baseline = _REGISTERED.get(self)
            if baseline is None:
                return False
            (expected_digest, fingerprints, max_sizes, acl_checker,
             expected_context, expected_bootstrap_authority) = baseline
            context = self.manifest_inputs.get("context")
            bootstrap_authority = self.manifest_inputs.get("bootstrap_authority")
            if (context is not expected_context
                    or _owner_login._ACCEPTED.get(id(context)) is not context
                    or bootstrap_authority is not expected_bootstrap_authority):
                return False
            current = hashlib.sha256(_canonical({
                "manifest_inputs": _redacted_projection(self.manifest_inputs),
                "prior_template": self.prior_template,
                "runtime_binding": self.runtime_binding,
                "bootstrap_template": self.bootstrap_template,
            })).hexdigest()
            if current != expected_digest:
                return False
            for fingerprint in fingerprints:
                if _read_snapshot_now(fingerprint, maximum=max_sizes[fingerprint[0]],
                                     acl_checker=acl_checker) != fingerprint:
                    return False
            return True
        except Exception:
            return False


def _redacted_projection(value: Any) -> Any:
    """Canonicalizable content only; secret-bearing fields are rejected upstream."""
    if isinstance(value, Mapping):
        return {str(k): _redacted_projection(v) for k, v in value.items()}
    if type(value) in (list, tuple):
        return [_redacted_projection(v) for v in value]
    if type(value) is bytes:
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if hasattr(value, "__dataclass_fields__"):
        return _redacted_projection(asdict(value))
    if type(value) in (str, int, float, bool) or value is None:
        return value
    raise ValueError


def load_owner_enrolled_private_inputs(
    *,
    owner_release_receipt: Path,
    owner_oauth_authorization_path: Path,
    owner_oauth_binding_path: Path,
    owner_oauth_state_dir: Path,
    mapit_bootstrap_authority_path: Path,
    mapit_bootstrap_state_dir: Path,
    mapit_publication_state_dir: Path,
    mapit_evidence_path: Path,
    synthetic_binding_path: Path,
    synthetic_authorization_path: Path,
    synthetic_state_dir: Path,
    invitation_authorization_path: Path,
    invitation_state_dir: Path,
    public_config_path: Path,
    prior_template: Mapping[str, Any],
    source_sha: str,
    acl_checker: Callable[[Path], bool] | None = None,
    jwks_fetcher: Callable[[str], bytes] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> OwnerEnrolledPrivateInputs:
    """Load and cross-check private lineage; never creates/renews authority.

    ``prior_template`` must be supplied from the separately bounded operator
    read of the existing closed stack. It is accepted only if the owning
    runtime evidence bundle pins the exact template and code digests.
    """
    if acl_checker is not None and not callable(acl_checker):
        _fail()
    if not callable(monotonic) or (jwks_fetcher is not None and not callable(jwks_fetcher)):
        _fail()
    if type(source_sha) is not str or _GIT_SHA.fullmatch(source_sha) is None or source_sha == "0" * 40:
        _fail()
    try:
        if not isinstance(prior_template, Mapping):
            raise ValueError
        # Capture every private file and journal before any owning parser reads
        # it. The final assertion repeats ACL, identity, size, timestamp and
        # digest checks after parsing and the two public fetches.
        path_specs = [
            (owner_release_receipt, 256 * 1024),
            (owner_oauth_authorization_path, 32 * 1024),
            (owner_oauth_binding_path, 16 * 1024),
            (mapit_bootstrap_authority_path, 32 * 1024),
            (mapit_evidence_path, 64 * 1024),
            (synthetic_binding_path, 32 * 1024),
            (synthetic_authorization_path, 32 * 1024),
            (invitation_authorization_path, 16 * 1024),
            (public_config_path, _MAX_PUBLIC_CONFIG_BYTES),
        ]
        fingerprints: list[tuple[Any, ...]] = []
        max_sizes: dict[str, int] = {}
        resolved_paths: dict[str, Path] = {}
        for path, maximum in path_specs:
            resolved, _raw, fingerprint = _snapshot(Path(path), maximum=maximum, acl_checker=acl_checker)
            if str(resolved) in max_sizes:
                raise ValueError
            fingerprints.append(fingerprint)
            max_sizes[str(resolved)] = maximum
            resolved_paths[str(Path(path))] = resolved

        for state_dir in (owner_oauth_state_dir, mapit_bootstrap_state_dir, mapit_publication_state_dir,
                          synthetic_state_dir, invitation_state_dir):
            _dir = validate_private_location(Path(state_dir), acl_checker=acl_checker)
            if not _dir.is_dir():
                raise ValueError
        for state_dir in (owner_oauth_state_dir, mapit_bootstrap_state_dir, mapit_publication_state_dir,
                          synthetic_state_dir, invitation_state_dir):
            maximum = 32 * 1024 if Path(state_dir) == Path(mapit_publication_state_dir) else 128 * 1024
            _path, _raw, fingerprint = _journal_file(Path(state_dir), maximum=maximum, acl_checker=acl_checker)
            if fingerprint[0] in max_sizes:
                raise ValueError
            fingerprints.append(fingerprint)
            max_sizes[fingerprint[0]] = maximum

        # The strict owner parsers establish original policy, OAuth client and
        # accepted receipt provenance; no candidate token or MAPIT session is read.
        owner_auth_path = resolved_paths[str(Path(owner_oauth_authorization_path))]
        owner_binding_path = resolved_paths[str(Path(owner_oauth_binding_path))]
        owner_release_path = resolved_paths[str(Path(owner_release_receipt))]
        owner_auth = load_authorization(owner_auth_path)
        owner_binding = _load_owner_binding(owner_binding_path, acl_checker=acl_checker)
        owner_state_dir = validate_private_location(Path(owner_oauth_state_dir), acl_checker=acl_checker)
        owner_state = FileJournal(owner_state_dir).load()
        trusted_owner = load_trusted_owner_policy(owner_release_path,
            expected_account=owner_auth["account"], acl_checker=acl_checker)
        context = parse_accepted_owner_login_context(owner_auth, owner_binding, owner_state,
            trusted_owner_policy=trusted_owner)
        resolved_owner_state = validate_private_location(Path(owner_oauth_state_dir),
            acl_checker=acl_checker)
        if (owner_binding.get("state_directory") != str(resolved_owner_state)
                or owner_binding.get("authorization_sha256") != hashlib.sha256(_canonical(owner_auth)).hexdigest()):
            raise ValueError

        # Load the accepted dedicated namespace through its owning parsers only.
        bootstrap_authority_path = resolved_paths[str(Path(mapit_bootstrap_authority_path))]
        mapit_authority, _mapit_source, _mapit_github, bootstrap_state, bootstrap_plan, _receipt = (
            _load_accepted_bootstrap(bootstrap_authority_path, Path(mapit_bootstrap_state_dir),
                                     _parser_only_clients(), acl_checker=acl_checker))
        runtime_bundle, _runtime_raw = _load_runtime_bundle(
            resolved_paths[str(Path(mapit_evidence_path))], acl_checker=acl_checker)
        if runtime_evidence_digest(runtime_bundle) != mapit_authority.runtime_evidence_sha256:
            raise ValueError
        runtime_binding = _validate_runtime_bundle(runtime_bundle, mapit_authority, bootstrap_plan.template)
        from scripts.dev_mapit_runtime_evidence import _validate_historical_bootstrap
        _validate_historical_bootstrap(
            clients=_parser_only_clients(), binding_path=Path(synthetic_binding_path),
            authorization_path=Path(synthetic_authorization_path), state_dir=Path(synthetic_state_dir),
            bundle=runtime_bundle, authority=mapit_authority, acl_checker=acl_checker)

        # Rebuild the exact closed predecessor; runtime evidence is a fingerprint,
        # not an alternate source of application configuration.
        prior, prior_keys, _bucket, prior_api, prior_account = _rebuild_prior(dict(prior_template))
        prior_code = prior["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"]
        expected_code_sha = prior_code.removeprefix("runtime/").removesuffix(".zip")
        expected_stack_prefix = (
            f"arn:aws:cloudformation:eu-west-1:{context.account}:stack/"
            "honda-mapit-mcp-dev-retained/"
        )
        if (prior_account != context.account or prior_api != context.policy.api_id
                or runtime_binding.get("account_id") != context.account
                or runtime_binding.get("operator_user_arn") != context.operator
                or runtime_binding.get("template_sha256") != hashlib.sha256(_canonical(prior)).hexdigest()
                or runtime_binding.get("code_sha256") != expected_code_sha
                or type(runtime_binding.get("app_stack_arn")) is not str
                or re.fullmatch(re.escape(expected_stack_prefix) + r"[0-9a-f-]{36}",
                                runtime_binding["app_stack_arn"]) is None):
            raise ValueError

        # Publication is a flat accepted journal, not the namespace CAS journal.
        _journal_file(Path(mapit_publication_state_dir), maximum=32 * 1024, acl_checker=acl_checker)
        publication_state = FileJournal(Path(mapit_publication_state_dir)).load()
        if type(publication_state) is not dict:
            raise ValueError
        from scripts.run_dev_mapit_binding_key_setup import _digest as _key_digest
        publication = _load_accepted_publication(Path(mapit_publication_state_dir), acl_checker=acl_checker,
            expected_receipt_sha256=_key_digest(publication_state))

        invitation_authority = _validate_invitation_authority(
            _read_invitation_json(resolved_paths[str(Path(invitation_authorization_path))], acl_checker=acl_checker),
            state_dir=Path(invitation_state_dir))
        invitation_state = FileJournal(validate_private_location(Path(invitation_state_dir),
            acl_checker=acl_checker)).load()

        config_path = resolved_paths[str(Path(public_config_path))]
        config = _load_config(config_path, acl_checker=acl_checker)
        if config.email is not None or config.password is not None:
            raise ValueError
        public_config = {name: getattr(config, name) for name in _CONFIG_FIELDS}
        if set(public_config) != _CONFIG_FIELDS:
            raise ValueError

        owner_url = _issuer_jwks_url(context.policy.issuer_url)
        mapit_url = _issuer_jwks_url(
            f"https://cognito-idp.eu-west-1.amazonaws.com/{config.user_pool_id}")
        fetch = jwks_fetcher or (lambda url: _fetch_jwks(url, monotonic=monotonic))
        invitation_jwks = fetch(owner_url)
        mapit_jwks = fetch(mapit_url)
        if (type(invitation_jwks) is not bytes or not 0 < len(invitation_jwks) <= _MAX_JWKS_BYTES
                or type(mapit_jwks) is not bytes or not 0 < len(mapit_jwks) <= _MAX_JWKS_BYTES):
            raise ValueError
        parse_cognito_jwks(invitation_jwks)
        parse_cognito_jwks(mapit_jwks)

        manifest_inputs = {
            "context": context, "bootstrap_authority": mapit_authority,
            "bootstrap_state": bootstrap_state, "publication": publication,
            "invitation_authority": invitation_authority, "invitation": invitation_state,
            "public_config": public_config, "source_sha": source_sha,
            "invitation_jwks": invitation_jwks, "mapit_jwks": mapit_jwks,
        }
        # Existing pure builder is the final cross-binding validator for owner,
        # bootstrap key, publication v1, invitation row and exact public config.
        build_owner_manifest(**manifest_inputs)

        # Recheck every input after all parsers/network reads, including state
        # journals, before returning any reusable projection.
        for fingerprint in fingerprints:
            if _read_snapshot_now(fingerprint, maximum=max_sizes[fingerprint[0]],
                                  acl_checker=acl_checker) != fingerprint:
                raise ValueError
        _projection = {"manifest_inputs": _redacted_projection(manifest_inputs),
            "prior_template": _redacted_projection(prior),
            "runtime_binding": _redacted_projection(runtime_binding),
            "bootstrap_template": _redacted_projection(bootstrap_plan.template)}
        object_digest = hashlib.sha256(_canonical(_projection)).hexdigest()
        result = OwnerEnrolledPrivateInputs(manifest_inputs=manifest_inputs, prior_template=prior,
            runtime_binding=runtime_binding, bootstrap_template=bootstrap_plan.template,
            fingerprints=tuple(fingerprints), max_sizes=max_sizes, acl_checker=acl_checker,
            object_digest=object_digest)
        with _REGISTRY_LOCK:
            _REGISTERED[result] = (
                object_digest, tuple(fingerprints), dict(max_sizes), acl_checker,
                manifest_inputs["context"], manifest_inputs["bootstrap_authority"],
            )
        return result
    except PrivateInputsError:
        raise
    except Exception:
        _fail()


__all__ = ["OwnerEnrolledPrivateInputs", "PrivateInputsError", "load_owner_enrolled_private_inputs"]
