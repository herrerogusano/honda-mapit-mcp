"""Explicit DEV-only request composition for an enrolled MAPIT provider.

No entrypoint, SDK discovery, default owner, enrollment writes or deployment.
The trusted caller supplies pinned configuration and public verification keys;
private resources are loaded only inside an authenticated durable request.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
import time
from typing import Any, Callable, Mapping

from .aws_binding_keys import BindingKeyMaterial
from .aws_identity_binding import DynamoDBIdentityBindingRegistry
from .cloud_transport import validate_cloud_config
from .config import MapitConfig
from .durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from .enrolled_provider import EnrolledCloudServicesProvider
from .mapit_identity import MapitIdentityVerifier
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority


@dataclass(frozen=True, repr=False)
class DevEnrolledReadResources:
    """In-memory resources from a trusted, independently validated key loader.

    The loader must validate key configuration/account/version before returning
    material. This value is not a persisted receipt or a substitute for IAM.
    No writer is supplied to the runtime registry, even if a client also has one.
    """
    binding_reader: Any = field(repr=False)
    session_reader: Any = field(repr=False)
    key_material: BindingKeyMaterial = field(repr=False)

    def __repr__(self):
        return "DevEnrolledReadResources(<redacted>)"


class DevEnrolledProviderFactory:
    """Fresh readonly binding/provider per exact router-authorized operation.

    Transports and resource loading are trusted explicit injection boundaries.
    This factory grants no invitations and publishes no sessions. The existing
    fixed-table registry contract remains intact; a new real-account namespace
    needs its own reviewed storage/key authority before deployment.
    """

    def __init__(self, *, account_id: str, config: MapitConfig,
                 mapit_public_keys: Mapping[str, bytes | str],
                 resources_loader: Callable[..., DevEnrolledReadResources],
                 transports_factory: Callable[..., tuple[Callable, Callable]],
                 namespace: str = "synthetic",
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 monotonic: Callable[[], float] = time.monotonic):
        if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or account_id == "0" * 12 or type(namespace) is not str or namespace not in {"synthetic", "mapit"}
                or not isinstance(mapit_public_keys, Mapping) or not mapit_public_keys
                or not all(callable(item) for item in (resources_loader, transports_factory, clock, monotonic))):
            raise ValueError("dev_enrolled_configuration_invalid")
        try:
            validate_cloud_config(config)
            # Validate and copy public material without any private resource read.
            public_keys = dict(mapit_public_keys)
            MapitIdentityVerifier(config, public_keys, b"\x00" * 32, clock=clock)
        except Exception:
            raise ValueError("dev_enrolled_configuration_invalid") from None
        self._account, self._config, self._public_keys = account_id, config, public_keys
        self._namespace = namespace
        self._load, self._transports = resources_loader, transports_factory
        self._clock, self._monotonic = clock, monotonic

    def __repr__(self):
        return "DevEnrolledProviderFactory(<redacted>)"

    def __call__(self, *, tenant_key: str, deadline: float,
                 authority: InvitedTenantAuthority, grant: AuthenticatedTenant,
                 durable_guard: DurableTenantGuard, snapshot: DurableTenantSnapshot,
                 request_check: Callable[[], None]):
        try:
            if (type(authority) is not InvitedTenantAuthority or not authority.matches_environment("dev")
                    or type(durable_guard) is not DurableTenantGuard or not durable_guard.is_bound_to(authority)
                    or type(grant) is not AuthenticatedTenant or tenant_key != grant.key
                    or type(snapshot) is not DurableTenantSnapshot or not callable(request_check)):
                raise ValueError
            def check():
                request_check()
                authority.validate(grant)
                durable_guard.check(grant, snapshot)
            check()
            sampled = self._monotonic()
            if (type(sampled) not in (int, float) or not math.isfinite(sampled)
                    or type(deadline) not in (int, float) or not math.isfinite(deadline)
                    or not 0 < deadline - sampled <= 14):
                raise ValueError
            resources = self._load(deadline=deadline)
            check()
            if type(resources) is not DevEnrolledReadResources or type(resources.key_material) is not BindingKeyMaterial:
                raise ValueError
            material = resources.key_material
            if (type(material.binding_mac_key) is not bytes or len(material.binding_mac_key) != 32
                    or type(material.identity_proof_hmac_key) is not bytes or len(material.identity_proof_hmac_key) != 32
                    or material.binding_mac_key == material.identity_proof_hmac_key):
                raise ValueError
            verifier = MapitIdentityVerifier(self._config, self._public_keys,
                material.identity_proof_hmac_key, clock=self._clock)
            transports = self._transports(deadline=deadline)
            check()
            if type(transports) is not tuple or len(transports) != 2 or not all(map(callable, transports)):
                raise ValueError
            auth_transport, mapit_transport = transports
            table_name = ("honda-mapit-mcp-dev-identity-bindings" if self._namespace == "synthetic"
                          else "honda-mapit-mcp-dev-mapit-identity-bindings")
            registry = DynamoDBIdentityBindingRegistry(resources.binding_reader, writer=None,
                table_arn=f"arn:aws:dynamodb:eu-west-1:{self._account}:table/{table_name}",
                account_id=self._account, authority=authority, durable_guard=durable_guard,
                environment="dev", config=self._config, verifier=verifier,
                namespace=self._namespace,
                binding_key=material.binding_mac_key, auth_transport=auth_transport,
                clock=self._clock, deadline=deadline, monotonic=self._monotonic)
            check()
            provider = EnrolledCloudServicesProvider(registry, authority=authority, grant=grant,
                durable_guard=durable_guard, snapshot=snapshot, ssm_client=resources.session_reader,
                account_id=self._account, auth_transport=auth_transport, mapit_transport=mapit_transport,
                deadline=deadline, monotonic=self._monotonic)
            check()
            return provider
        except Exception:
            raise ValueError("dev_enrolled_provider_failed") from None


def compose_enrolled_dev_runtime(manifest_raw: bytes, invitation_jwks: bytes, mapit_jwks: bytes, *,
        manifest_digest: str, account_id: str, authorization_reader: Any,
        resources_loader: Callable[..., DevEnrolledReadResources],
        transports_factory: Callable[..., tuple[Callable, Callable]],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic):
    """Bind the private manifest to the actual request-local MCP composition.

    This is injected/offline-capable composition, not a Lambda entrypoint or an
    assertion of hosted acceptance. Resources must be independently provisioned
    and verified; real MAPIT acquisition remains an explicit operator flow.
    """
    from .aws_durable_tenants import DynamoDBTenantStore
    from .dev_enrolled_manifest import parse_enrolled_dev_manifest
    from .invited_lambda import create_invited_dev_lambda_runtime
    manifest = parse_enrolled_dev_manifest(manifest_raw, invitation_jwks, mapit_jwks,
        expected_digest=manifest_digest, account_id=account_id)
    store = DynamoDBTenantStore(authorization_reader, table_arn=manifest.authorization_table_arn,
        allowed_keys=tuple(manifest.policies))
    factory = DevEnrolledProviderFactory(account_id=account_id, config=manifest.config,
        mapit_public_keys=manifest.mapit_keys, resources_loader=resources_loader,
        transports_factory=transports_factory, namespace="mapit", clock=clock, monotonic=monotonic)
    return create_invited_dev_lambda_runtime(next(iter(manifest.policies.values())),
        manifest.policies, manifest.invitation_keys, contextual_provider_factory=factory,
        authorization_store=store)


__all__ = ["DevEnrolledReadResources", "DevEnrolledProviderFactory", "compose_enrolled_dev_runtime"]
