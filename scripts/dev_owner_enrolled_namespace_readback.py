"""Readonly post-publication namespace checks, before any MAPIT enrollment.

This helper needs accepted private evidence supplied by its owning operator.
It neither loads keys nor proves the app runtime or an enrolled session. The
caller must wrap SDK clients with its bounded, same-credential read capability.
The historical pre-publication verifier remains unchanged in behavior.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re

from scripts.run_dev_mapit_binding_key_setup import (
    CONFIG_PARAMETER, OPERATOR_ROLE_NAME, REGION,
    _verify_current_bootstrap_resources,
)

_FIELDS = frozenset({"schema", "operation", "namespace", "account", "source",
    "run_id", "bootstrap_sha256", "parameter_path", "start", "end", "phase"})


def verify_published_namespace(clients, authority, state, plan, receipt_digest,
                               publication, counter, started, deadline, monotonic):
    """Exact retained empty-binding namespace plus accepted config v1 metadata.

    No decrypted/ciphertext parameter value is requested. This is intentionally
    a pre-enrollment contract: tenant session paths and binding document must
    still be absent. Accepted publication evidence is historical, not replayed.
    """
    try:
        if (type(publication) is not dict or set(publication) != _FIELDS
                or type(publication["schema"]) is not int or publication["schema"] != 1
                or publication["operation"] != "dev_mapit_binding_key_publication"
                or publication["namespace"] != "mapit" or publication["phase"] != "accepted"
                or publication["account"] != authority.account_id
                or publication["bootstrap_sha256"] != receipt_digest
                or publication["parameter_path"] != CONFIG_PARAMETER
                or type(publication["source"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", publication["source"]) is None
                or publication["source"] == "0" * 40
                or type(publication["run_id"]) is not int or publication["run_id"] <= 0
                or publication["run_id"] == authority.run_id
                or type(publication["start"]) is not int or type(publication["end"]) is not int
                or publication["start"] <= 0
                or not 0 < publication["end"] - publication["start"] <= 600):
            raise ValueError
        _verify_current_bootstrap_resources(clients, authority, state, plan,
            receipt_digest, counter, started, deadline, monotonic)
        reply = clients["ssm"].describe_parameters(ParameterFilters=[{
            "Key": "Name", "Option": "Equals", "Values": [CONFIG_PARAMETER]}], MaxResults=5)
        rows = reply.get("Parameters") if isinstance(reply, Mapping) else None
        if (not isinstance(reply, Mapping)
                or type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or reply["ResponseMetadata"]["HTTPStatusCode"] != 200
                or any(reply.get(name) not in (None, "") for name in ("NextToken", "NextMarker", "Marker"))
                or type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping)):
            raise ValueError
        row = rows[0]
        changed = row.get("LastModifiedDate")
        expected_user = (f"arn:aws:sts::{authority.account_id}:assumed-role/"
                         f"{OPERATOR_ROLE_NAME}/mapit-key-{publication['run_id']}")
        if (row.get("Name") != CONFIG_PARAMETER or row.get("Type") != "SecureString"
                or type(row.get("Version")) is not int or row["Version"] != 1
                or row.get("Tier") != "Standard" or row.get("DataType") != "text"
                or row.get("KeyId") not in {"alias/aws/ssm", authority.ssm_key_arn,
                                             authority.ssm_key_arn.rsplit("/", 1)[-1]}
                or row.get("LastModifiedUser") != expected_user
                or not isinstance(changed, datetime) or changed.tzinfo is None
                or not publication["start"] <= changed.timestamp() < publication["end"]
                or row.get("Policies") not in (None, [])):
            raise ValueError
        for key in authority._tenant_keys:
            path = f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
            try:
                clients["ssm"].get_parameter(Name=path, WithDecryption=False)
            except Exception as exc:
                error_reply = getattr(exc, "response", {})
                if (not isinstance(error_reply, Mapping)
                        or error_reply.get("Error", {}).get("Code") != "ParameterNotFound"
                        or type(error_reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                        or error_reply["ResponseMetadata"]["HTTPStatusCode"] != 400):
                    raise ValueError from None
            else:
                raise ValueError
        return {"verified": True, "config_version": 1,
                "table_id": state["readback_receipt"]["table_id"],
                "binding_empty": True, "sessions_absent": True}
    except Exception:
        raise ValueError("published_namespace_unverified") from None
