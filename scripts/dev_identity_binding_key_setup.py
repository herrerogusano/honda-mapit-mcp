"""One create-only protected key publication; no credential discovery or retry."""
from __future__ import annotations

import math
import re
import time

from mapit.aws_binding_keys import (PARAMETER_PATH, encode_binding_keys, generate_binding_keys,
                                   load_binding_keys)
from scripts.build_aws_dev_identity_binding_bootstrap import OPERATOR_ROLE_NAME


def publish_keys(clients, journal, *, account_id, config, source_sha, run_id,
                 bootstrap_sha256, start, end, clock=time.time, monotonic=time.monotonic):
    """Injected trusted operator core. Uncertain PUT leaves a consumed intent.

    The caller must verify fresh source/protections and the accepted bootstrap
    receipt before entry. This function never logs or journals key bytes/hashes.
    A subsequent process may read/reconcile, never repeat this publication.
    """
    try:
        if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or account_id == "0" * 12 or type(source_sha) is not str
                or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
                or type(bootstrap_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", bootstrap_sha256) is None
                or type(run_id) is not int or run_id <= 0 or type(start) is not int or type(end) is not int
                or not 0 < end - start <= 3600 or set(clients) != {"sts", "ssm"}):
            raise ValueError
        first = monotonic()
        if type(first) not in (int, float) or not math.isfinite(first):
            raise ValueError
        sts_meta = clients["sts"].meta
        sts_config = sts_meta.config
        if (sts_meta.service_model.service_name != "sts" or sts_meta.region_name != "eu-west-1"
                or sts_meta.endpoint_url != "https://sts.eu-west-1.amazonaws.com"
                or type(sts_config.retries.get("total_max_attempts")) is not int
                or sts_config.retries["total_max_attempts"] != 1
                or any(type(t) not in (int, float) or not math.isfinite(t) or not 0 < t <= 3
                       for t in (sts_config.connect_timeout, sts_config.read_timeout))):
            raise ValueError
        last = first
        def fresh():
            nonlocal last
            now, epoch = monotonic(), clock()
            if (type(now) not in (int, float) or not math.isfinite(now) or now < last or now - first >= 14
                    or type(epoch) not in (int, float) or not math.isfinite(epoch) or not start <= epoch < end):
                raise ValueError
            last = now
        def identity(client, expected):
            fresh()
            if client is not clients["ssm"] or expected != account_id:
                return False
            reply = clients["sts"].get_caller_identity()
            fresh()
            arn = reply.get("Arn")
            return (type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is int
                and reply["ResponseMetadata"]["HTTPStatusCode"] == 200 and reply.get("Account") == account_id
                and type(arn) is str and re.fullmatch(
                    rf"arn:aws:sts::{account_id}:assumed-role/{OPERATOR_ROLE_NAME}/[A-Za-z0-9+=,.@_-]{{2,64}}", arn) is not None)
        with journal.locked():
            if journal.load() is not None:
                return {"ok": False, "category": "key_publication_consumed"}
            if identity(clients["ssm"], account_id) is not True:
                raise ValueError
            # Validate the explicit SSM client before any write, using its model
            # configuration (the pinned loader performs the same read checks).
            meta, cfg = clients["ssm"].meta, clients["ssm"].meta.config
            if (meta.service_model.service_name != "ssm" or meta.region_name != "eu-west-1"
                    or meta.endpoint_url != "https://ssm.eu-west-1.amazonaws.com"
                    or type(cfg.retries.get("total_max_attempts")) is not int
                    or cfg.retries["total_max_attempts"] != 1
                    or any(type(t) not in (int, float) or not math.isfinite(t) or not 0 < t <= 3
                           for t in (cfg.connect_timeout, cfg.read_timeout))):
                raise ValueError
            try:
                clients["ssm"].get_parameter(Name=PARAMETER_PATH + ":1", WithDecryption=False)
            except Exception as exc:
                response = getattr(exc, "response", {})
                if (response.get("Error", {}).get("Code") != "ParameterNotFound"
                        or type(response.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                        or response["ResponseMetadata"]["HTTPStatusCode"] != 400):
                    raise ValueError from None
            else:
                raise ValueError
            fresh()
            material = generate_binding_keys()
            value = encode_binding_keys(material, account_id=account_id, config=config)
            state = {"schema": 1, "operation": "dev_identity_binding_key_publication", "account": account_id,
                "source": source_sha, "run_id": run_id, "bootstrap_sha256": bootstrap_sha256,
                "parameter_path": PARAMETER_PATH, "start": start, "end": end, "phase": "put_intent"}
            journal.save(state)
            fresh()
            reply = clients["ssm"].put_parameter(Name=PARAMETER_PATH, Value=value,
                Type="SecureString", KeyId="alias/aws/ssm", Overwrite=False, Tier="Standard", DataType="text")
            fresh()
            if (type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                    or reply["ResponseMetadata"]["HTTPStatusCode"] != 200
                    or type(reply.get("Version")) is not int or reply["Version"] != 1 or reply.get("Tier") != "Standard"):
                raise ValueError
            loaded = load_binding_keys(clients["ssm"], account_id=account_id, config=config,
                account_verifier=identity, deadline=first + 14, monotonic=monotonic)
            if loaded != material:
                raise ValueError
            fresh()
            state["phase"] = "accepted"
            journal.save(state)
            return {"ok": True, "category": "protected_key_handoff_verified"}
    except Exception:
        return {"ok": False, "category": "key_publication_unverified"}
