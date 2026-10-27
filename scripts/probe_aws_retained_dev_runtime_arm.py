"""Offline ARM probe for the retained-dev synthetic runtime candidate.

This probe builds the separate retained-dev archive from explicit local,
hash-locked wheels and a generated public JWKS fixture, then (when invoked)
executes it in the pinned Lambda ARM image with Docker networking disabled.
No AWS client, credential, MAPIT session, or production builder is used.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mapit.aws_dev_runtime import cognito_dev_policy
from scripts import build_aws_dev_runtime as historical
from scripts import build_aws_retained_dev_archive as builder
from scripts import probe_aws_dev_runtime_arm as docker_helpers
from scripts.build_aws_retained_dev_runtime import (
    build_retained_dev_manifest,
    RETAINED_DEV_MANIFEST_FILENAME,
    SYNTHETIC_CLIENT_ID,
    SYNTHETIC_EXECUTION_END,
    SYNTHETIC_EXECUTION_START,
    SYNTHETIC_OWNER_SUBJECT,
    SYNTHETIC_USER_POOL_ID,
)

IMAGE = docker_helpers.IMAGE
SOURCE_SHA = "a" * 40
API_ID = "a1b2c3d4e5"
_KID = "offline-retained-dev-arm-probe-key"
_MAX_OUTPUT = 8 * 1024
_MAX_SECONDS = 240
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CHECKS = (
    "archive_digest", "manifest_digest", "manifest_bindings", "native_imports",
    "initialize", "tools_list_exactly_ten", "tool_calls_all_succeeded", "warm_repeat",
    "missing_auth_401", "unknown_kid_401", "wrong_audience_401", "wrong_scope_403",
    "prod_isolation_503", "missing_config_503", "jwks_mismatch_503", "window_expiry_503",
)
_SAFE_FAILURES = frozenset({
    "wheel_directory_invalid", "temporary_directory_invalid", "local_docker_context_unavailable",
    "arm_probe_output_invalid", "arm_probe_execution_failed", "cleanup_unverified",
    "retained_dev_runtime_arm_probe_failed",
})


def _run_bounded_process(command: list[str], input_text: str, *, timeout: float) -> tuple[int, str]:
    """Run one child with bounded stdout/stderr and a hard timeout."""
    process = None
    overflow = threading.Event()
    writer_failed = threading.Event()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, bufsize=0)
    except Exception:
        raise ValueError("arm_probe_execution_failed") from None

    def kill_child() -> None:
        try:
            if process is not None and process.poll() is None:
                process.kill()
        except Exception:
            pass

    def read_pipe(name: str, stream: Any) -> None:
        try:
            while True:
                remaining = _MAX_OUTPUT + 1 - len(buffers[name])
                chunk = stream.read(min(4096, max(1, remaining)))
                if not chunk:
                    return
                if len(buffers[name]) + len(chunk) > _MAX_OUTPUT:
                    overflow.set(); kill_child(); return
                buffers[name].extend(chunk)
        except Exception:
            overflow.set(); kill_child()

    def write_input() -> None:
        try:
            assert process is not None and process.stdin is not None
            process.stdin.write(input_text.encode("utf-8", errors="strict")); process.stdin.flush()
        except Exception:
            writer_failed.set()
        finally:
            try:
                if process is not None and process.stdin is not None:
                    process.stdin.close()
            except Exception:
                pass

    assert process.stdout is not None and process.stderr is not None
    readers = [threading.Thread(target=read_pipe, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for reader in readers:
        reader.start()
    writer = threading.Thread(target=write_input, daemon=True); writer.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True; kill_child()
        try: process.wait(timeout=2)
        except Exception: pass
    except Exception:
        kill_child()
        try: process.wait(timeout=2)
        except Exception: pass
        raise ValueError("arm_probe_execution_failed") from None
    writer.join(timeout=2)
    for reader in readers:
        reader.join(timeout=2)
    if timed_out or overflow.is_set():
        raise ValueError("arm_probe_output_invalid" if overflow.is_set() else "arm_probe_execution_failed")
    if writer.is_alive() or any(reader.is_alive() for reader in readers) or writer_failed.is_set():
        raise ValueError("arm_probe_execution_failed")
    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
        return_code = process.returncode
    except Exception:
        raise ValueError("arm_probe_output_invalid") from None
    if type(return_code) is not int:
        raise ValueError("arm_probe_execution_failed")
    return return_code, stdout


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fixture(now: int | None = None, *, api_id: str = API_ID, execution_start_epoch: int = SYNTHETIC_EXECUTION_START) -> tuple[bytes, dict[str, str]]:
    if now is None:
        now = execution_start_epoch + 60
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    snapshot = json.dumps({"keys": [{
        "kty": "RSA", "kid": _KID, "use": "sig", "alg": "RS256",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }]}, sort_keys=True, separators=(",", ":")).encode("ascii")
    policy = cognito_dev_policy(
        user_pool_id=SYNTHETIC_USER_POOL_ID, api_id=api_id,
        client_id=SYNTHETIC_CLIENT_ID, owner_subject=SYNTHETIC_OWNER_SUBJECT,
    )

    def signed(kid: str = _KID, **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
            "client_id": policy.client_id, "token_use": "access", "iat": now,
            "exp": now + 240, "scope": policy.required_scope,
        }
        claims.update(overrides)
        header = _b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
        body = _b64u(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signing = f"{header}.{body}".encode("ascii")
        signature = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{body}.{_b64u(signature)}"

    return snapshot, {
        "valid": signed(),
        "unknown_kid": signed("unknown-retained-key"),
        "wrong_audience": signed(aud="https://wrong.invalid/mcp"),
        "wrong_scope": signed(scope="https://wrong.invalid/mcp/use"),
    }


_CONTAINER_PROBE = r'''import base64,hashlib,json,os,sys,tempfile,time,zipfile
from pathlib import Path
CHECKS=("archive_digest","manifest_digest","manifest_bindings","native_imports","initialize","tools_list_exactly_ten","tool_calls_all_succeeded","warm_repeat","missing_auth_401","unknown_kid_401","wrong_audience_401","wrong_scope_403","prod_isolation_503","missing_config_503","jwks_mismatch_503","window_expiry_503")
p=json.loads(sys.stdin.read(8192)); out={key:False for key in CHECKS}
try:
 raw=Path("/probe/runtime.zip").read_bytes(); assert hashlib.sha256(raw).hexdigest()==p["zip_sha256"]
 out["archive_digest"]=True
 root=Path(tempfile.mkdtemp(prefix="retained-dev-arm-probe-"))
 with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
  infos=archive.infolist(); assert len(infos)<=30000 and sum(i.file_size for i in infos)<=100*1024*1024
  for info in infos:
   path=__import__("pathlib").PurePosixPath(info.filename); assert not path.is_absolute() and ".." not in path.parts and "\\" not in info.filename
  manifest_raw=archive.read("mapit/retained-dev.manifest.json")
  jwks_raw=archive.read("mapit/cognito-public-jwks.json")
  assert hashlib.sha256(manifest_raw).hexdigest()==p["manifest_sha256"]
  assert hashlib.sha256(jwks_raw).hexdigest()==p["jwks_sha256"]
  manifest=json.loads(manifest_raw)
  assert manifest=={"api_id":p["api_id"],"builder":"build_retained_dev_runtime","environment":"dev","execution_end_epoch":p["execution_end_epoch"],"execution_start_epoch":p["execution_start_epoch"],"jwks_sha256":p["jwks_sha256"],"schema":1,"source_sha":p["source_sha"],"synthetic":True}
  out["manifest_digest"]=True; out["manifest_bindings"]=True
  archive.extractall(root)
 now=float(p["execution_start_epoch"]+60)
 sys.path.insert(0,str(root))
 import mapit.aws_dev_entrypoint as ep
 import mapit.remote_http as remote_http
 ep._clock=lambda:now; remote_http.time.time=lambda:now
 os.environ.update({"MAPIT_MCP_ENV":"dev","AWS_REGION":"eu-west-1","MAPIT_COGNITO_USER_POOL_ID":p["user_pool_id"],"MAPIT_API_ID":p["api_id"],"MAPIT_COGNITO_CLIENT_ID":p["client_id"],"MAPIT_OWNER_SUBJECT":p["owner_subject"],"MAPIT_COGNITO_JWKS_SHA256":p["jwks_sha256"],"MAPIT_DEV_EXECUTION_START_EPOCH":str(p["execution_start_epoch"]),"MAPIT_DEV_EXECUTION_END_EPOCH":str(p["execution_end_epoch"])})
 import cryptography.hazmat.bindings._rust
 out["native_imports"]=True
 class C:
  def get_remaining_time_in_millis(self): return 30000
 def rpc(method,params=None,ident=1): return json.dumps({"jsonrpc":"2.0","id":ident,"method":method,"params":params or {}},separators=(",",":"))
 def invoke(token,body):
  headers={"host":p["api_id"]+".execute-api.eu-west-1.amazonaws.com","content-type":"application/json","content-length":str(len(body.encode())),"accept":"application/json, text/event-stream"}
  if token is not None: headers["authorization"]="Bearer "+token
  event={"version":"2.0","rawPath":"/mcp","rawQueryString":"","headers":headers,"requestContext":{"stage":"$default","http":{"method":"POST","path":"/mcp"}},"body":body,"isBase64Encoded":False}
  return ep.handler(event,C())
 def parsed(response):
  try:return json.loads(response.get("body",""))
  except Exception:return {}
 token=p["tokens"]["valid"]
 init=parsed(invoke(token,rpc("initialize",{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"retained-dev-arm-probe","version":"1"}})))
 out["initialize"]=isinstance(init.get("result"),dict) and init.get("result",{}).get("protocolVersion")=="2025-03-26" and "error" not in init
 listing=parsed(invoke(token,rpc("tools/list"))); names=[x.get("name") for x in listing.get("result",{}).get("tools",[])]
 expected=["get_vehicle_status","get_vehicle_details","list_routes","get_route_detail","get_distance","compare_distance_periods","get_route_statistics","get_distance_breakdown","get_route_extremes","compare_route_periods"]
 out["tools_list_exactly_ten"]=len(names)==10 and set(names)==set(expected)
 rng={"from_time":"2026-01-01","to_time":"2026-02-01"}; period={"period_a":rng,"period_b":{"from_time":"2026-02-01","to_time":"2026-03-01"}}
 calls=[("get_vehicle_status",{}),("get_vehicle_details",{}),("list_routes",rng),("get_route_detail",{"route_id":"synthetic-route"}),("get_distance",rng),("compare_distance_periods",period),("get_route_statistics",rng),("get_distance_breakdown",dict(rng,group_by="day")),("get_route_extremes",rng),("compare_route_periods",period)]
 good=0
 for i,(name,args) in enumerate(calls,1):
  result=parsed(invoke(token,rpc("tools/call",{"name":name,"arguments":args},i))).get("result",{}); good += result.get("isError") is False
 out["tool_calls_all_succeeded"]=good==10
 a=parsed(invoke(token,rpc("tools/list"))); b=parsed(invoke(token,rpc("tools/list"))); out["warm_repeat"]=[x.get("name") for x in a.get("result",{}).get("tools",[])]==[x.get("name") for x in b.get("result",{}).get("tools",[])]==expected
 out["missing_auth_401"]=invoke(None,rpc("tools/list")).get("statusCode")==401
 out["unknown_kid_401"]=invoke(p["tokens"]["unknown_kid"],rpc("tools/list")).get("statusCode")==401
 out["wrong_audience_401"]=invoke(p["tokens"]["wrong_audience"],rpc("tools/list")).get("statusCode")==401
 out["wrong_scope_403"]=invoke(p["tokens"]["wrong_scope"],rpc("tools/list")).get("statusCode")==403
 def clear(): ep._CACHED_RUNTIME=None; ep._CACHED_JWKS_SHA256=None; ep._CACHED_WINDOW=None
 os.environ["MAPIT_MCP_ENV"]="prod"; clear(); out["prod_isolation_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
 os.environ["MAPIT_MCP_ENV"]="dev"; os.environ.pop("MAPIT_API_ID",None); clear(); out["missing_config_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
 os.environ["MAPIT_API_ID"]=p["api_id"]; os.environ["MAPIT_COGNITO_JWKS_SHA256"]="0"*64; clear(); out["jwks_mismatch_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
 os.environ["MAPIT_COGNITO_JWKS_SHA256"]=p["jwks_sha256"]; os.environ["MAPIT_DEV_EXECUTION_END_EPOCH"]=str(p["execution_end_epoch"]); ep._clock=lambda:float(p["execution_end_epoch"]); clear(); out["window_expiry_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
except BaseException: pass
print(json.dumps({"checks":out},sort_keys=True,separators=(",",":")))
sys.exit(0 if all(out.values()) else 2)
'''


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("candidate_json_invalid")
        value[key] = item
    return value


def _read_candidate_archive(path: Path) -> bytes:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ValueError("candidate_archive_invalid")
    try:
        repo = historical._repo_root()
        if historical._has_symlink_or_reparse_ancestor(path):
            raise ValueError("candidate_archive_invalid")
        resolved = historical._outside_repo_and_onedrive(path, repo, "candidate_archive_invalid")
        size = path.stat().st_size
        if type(size) is not int or size <= 0 or size > builder.MAX_ARCHIVE_BYTES:
            raise ValueError("candidate_archive_invalid")
        with resolved.open("rb") as stream:
            body = stream.read(builder.MAX_ARCHIVE_BYTES + 1)
    except ValueError:
        raise
    except Exception:
        raise ValueError("candidate_archive_invalid") from None
    if len(body) != size or len(body) <= 0 or len(body) > builder.MAX_ARCHIVE_BYTES:
        raise ValueError("candidate_archive_invalid")
    return body


def _validate_synthetic_tokens(tokens: Mapping[str, str]) -> None:
    if not isinstance(tokens, Mapping) or set(tokens) != {"valid", "unknown_kid", "wrong_audience", "wrong_scope"}:
        raise ValueError("synthetic_tokens_invalid")
    for value in tokens.values():
        if type(value) is not str or len(value) > 8192 or value.count(".") != 2 or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}", value):
            raise ValueError("synthetic_tokens_invalid")


def _validate_candidate_archive(path: Path, receipt: builder.RetainedDevBuildReceipt, tokens: Mapping[str, str]) -> tuple[bytes, int]:
    """Validate a sealed builder output before any container invocation.

    Only the sealed receipt and bounded archive bytes cross this boundary; the
    caller cannot substitute a loose manifest, digest, or token mapping.
    """
    if not isinstance(receipt, builder.RetainedDevBuildReceipt) or not receipt.validate():
        raise ValueError("candidate_receipt_invalid")
    if (
        type(receipt.source_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", receipt.source_sha) or receipt.source_sha == "0" * 40
        or type(receipt.api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", receipt.api_id)
        or type(receipt.jwks_sha256) is not str or not _HEX64.fullmatch(receipt.jwks_sha256)
        or type(receipt.zip_sha256) is not str or not _HEX64.fullmatch(receipt.zip_sha256)
        or type(receipt.manifest_sha256) is not str or not _HEX64.fullmatch(receipt.manifest_sha256)
        or type(receipt.execution_start_epoch) is not int or isinstance(receipt.execution_start_epoch, bool)
        or type(receipt.execution_end_epoch) is not int or isinstance(receipt.execution_end_epoch, bool)
        or receipt.execution_start_epoch <= 0 or receipt.execution_end_epoch <= receipt.execution_start_epoch
        or receipt.execution_end_epoch - receipt.execution_start_epoch > 300
        or type(receipt.archive_entries) is not int or receipt.archive_entries <= 0 or receipt.archive_entries > 30000
        or type(receipt.wheel_count) is not int or receipt.wheel_count < 0
        or type(receipt.source_modules) is not int or receipt.source_modules < 0
        or type(receipt.public_key_count) is not int or receipt.public_key_count != 1
    ):
        raise ValueError("candidate_receipt_invalid")
    _validate_synthetic_tokens(tokens)
    body = _read_candidate_archive(path)
    if hashlib.sha256(body).hexdigest() != receipt.zip_sha256:
        raise ValueError("candidate_digest_mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            if len(infos) != receipt.archive_entries or len(infos) > 30000 or sum(info.file_size for info in infos) > 100 * 1024 * 1024:
                raise ValueError("candidate_archive_shape_invalid")
            names: set[str] = set()
            for info in infos:
                if type(info.filename) is not str or len(info.filename) > 512:
                    raise ValueError("candidate_archive_shape_invalid")
                if info.filename in names:
                    raise ValueError("candidate_archive_shape_invalid")
                names.add(info.filename)
                path_name = __import__("pathlib").PurePosixPath(info.filename)
                if path_name.is_absolute() or ".." in path_name.parts or "\\" in info.filename:
                    raise ValueError("candidate_archive_shape_invalid")
            manifest_raw = archive.read(f"mapit/{RETAINED_DEV_MANIFEST_FILENAME}")
            jwks_raw = archive.read(f"mapit/{builder.JWKS_SNAPSHOT_FILENAME}")
            jwks_manifest_raw = archive.read(f"mapit/{builder.JWKS_MANIFEST_FILENAME}")
    except ValueError:
        raise
    except Exception:
        raise ValueError("candidate_archive_shape_invalid") from None
    if len(manifest_raw) > builder.MAX_MANIFEST_BYTES or len(jwks_manifest_raw) > builder.MAX_MANIFEST_BYTES:
        raise ValueError("candidate_archive_shape_invalid")
    if hashlib.sha256(manifest_raw).hexdigest() != receipt.manifest_sha256 or hashlib.sha256(jwks_raw).hexdigest() != receipt.jwks_sha256:
        raise ValueError("candidate_manifest_digest_mismatch")
    try:
        manifest = json.loads(manifest_raw, object_pairs_hook=_reject_duplicate_pairs)
        jwks_manifest = json.loads(jwks_manifest_raw, object_pairs_hook=_reject_duplicate_pairs)
        jwks = json.loads(jwks_raw, object_pairs_hook=_reject_duplicate_pairs)
        policy = cognito_dev_policy(user_pool_id=SYNTHETIC_USER_POOL_ID, api_id=receipt.api_id, client_id=SYNTHETIC_CLIENT_ID, owner_subject=SYNTHETIC_OWNER_SUBJECT)
        expected_manifest = build_retained_dev_manifest(receipt.source_sha, receipt.api_id, receipt.jwks_sha256, receipt.execution_start_epoch, receipt.execution_end_epoch)
        expected_jwks_manifest = {"issuer": policy.issuer_url, "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json", "sha256": receipt.jwks_sha256}
    except Exception:
        raise ValueError("candidate_manifest_invalid") from None
    if manifest != expected_manifest or jwks_manifest != expected_jwks_manifest or not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list) or len(jwks["keys"]) != receipt.public_key_count:
        raise ValueError("candidate_manifest_binding_mismatch")
    return body, len(infos)


def _command(archive: Path, *, context: str, name: str, run_id: str, cid_file: Path) -> list[str]:
    return [
        "docker", "--context", context, "run", "--rm", "--pull=never", "-i",
        "--name", name, "--label", f"{docker_helpers._OWNER_LABEL}=honda-mapit-mcp",
        "--label", f"{docker_helpers._RUN_LABEL}={run_id}", "--cidfile", str(cid_file),
        "--platform", "linux/arm64", "--network", "none", "--memory", "256m",
        "--mount", f"type=bind,source={archive.resolve()},target=/probe/runtime.zip,readonly",
        "--entrypoint", "python3", IMAGE, "-c", _CONTAINER_PROBE,
    ]


def _parse_checks(stdout: str) -> dict[str, bool]:
    if type(stdout) is not str or not stdout or len(stdout.encode("utf-8", errors="ignore")) > _MAX_OUTPUT:
        raise ValueError("arm_probe_output_invalid")
    try:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate")
                value[key] = item
            return value
        value = json.loads(stdout, object_pairs_hook=reject_duplicates)
    except Exception:
        raise ValueError("arm_probe_output_invalid") from None
    checks = value.get("checks") if isinstance(value, dict) and set(value) == {"checks"} else None
    if type(checks) is not dict or set(checks) != set(_CHECKS) or any(type(checks[name]) is not bool for name in _CHECKS):
        raise ValueError("arm_probe_output_invalid")
    return checks


def probe_candidate_archive(
    archive_path: Path,
    receipt: builder.RetainedDevBuildReceipt,
    tokens: Mapping[str, str],
    *,
    docker_context: str | None = None,
) -> dict[str, Any]:
    """Run the bounded ARM probe against one sealed candidate archive.

    Candidate bytes are read once, validated against the opaque builder
    receipt, then copied into a private temporary mount.  The returned shape
    contains only booleans, a category, and bounded counts; it never exposes
    archive paths, identifiers, tokens, digests, or container output.
    """
    body, entry_count = _validate_candidate_archive(archive_path, receipt, tokens)
    context = docker_helpers._docker_context()
    if docker_context is not None and docker_context != context:
        raise ValueError("local_docker_context_unavailable")
    if type(context) is not str or not context or len(context) > 128 or any(ord(char) < 0x20 for char in context):
        raise ValueError("local_docker_context_unavailable")
    with tempfile.TemporaryDirectory(prefix="honda-mapit-retained-dev-arm-candidate-") as scratch:
        root = Path(scratch).resolve(strict=True)
        repo = historical._repo_root()
        historical._outside_repo_and_onedrive(root, repo, "temporary_directory_invalid")
        candidate = root / "runtime.zip"
        cid_file = root / "container.cid"
        candidate.write_bytes(body)
        run_id = uuid.uuid4().hex
        name = f"honda-mapit-retained-dev-arm-probe-{run_id}"
        payload = json.dumps({
            "zip_sha256": receipt.zip_sha256,
            "manifest_sha256": receipt.manifest_sha256,
            "jwks_sha256": receipt.jwks_sha256,
            "source_sha": receipt.source_sha,
            "api_id": receipt.api_id,
            "user_pool_id": SYNTHETIC_USER_POOL_ID,
            "client_id": SYNTHETIC_CLIENT_ID,
            "owner_subject": SYNTHETIC_OWNER_SUBJECT,
            "execution_start_epoch": receipt.execution_start_epoch,
            "execution_end_epoch": receipt.execution_end_epoch,
            "tokens": dict(tokens),
            "checks": _CHECKS,
        }, separators=(",", ":"))
        try:
            status, stdout = _run_bounded_process(
                _command(candidate, context=context, name=name, run_id=run_id, cid_file=cid_file),
                payload,
                timeout=_MAX_SECONDS,
            )
        finally:
            try:
                cleaned = docker_helpers._cleanup_owned_container(context, name, run_id, cid_file)
            except Exception:
                cleaned = False
        if not cleaned:
            raise ValueError("cleanup_unverified")
        checks = _parse_checks(stdout)
        success = status == 0 and all(checks.values())
        return {
            "success": success,
            "category": "retained_dev_runtime_arm_probe_passed" if success else "retained_dev_runtime_arm_probe_failed",
            "archive_bytes": len(body),
            "archive_entries": entry_count,
            "checks": checks,
        }


def run_probe(wheel_dir: Path) -> dict[str, Any]:
    """Build and optionally execute the retained-dev candidate in ARM Docker."""
    try:
        if not isinstance(wheel_dir, Path):
            raise ValueError("wheel_directory_invalid")
        repo = historical._repo_root()
        wheels = historical._validate_external_wheel_dir(wheel_dir, repo)
        jwks, tokens = _fixture(SYNTHETIC_EXECUTION_START + 60, api_id=API_ID, execution_start_epoch=SYNTHETIC_EXECUTION_START)
        with tempfile.TemporaryDirectory(prefix="honda-mapit-retained-dev-arm-probe-") as scratch:
            root = Path(scratch).resolve(strict=True)
            historical._outside_repo_and_onedrive(root, repo, "temporary_directory_invalid")
            jwks_path, archive_path = root / "public-jwks.json", root / "runtime.zip"
            jwks_path.write_bytes(jwks)
            summary = builder.build_retained_dev_archive(
                wheels, jwks_path, archive_path, source_sha=SOURCE_SHA, api_id=API_ID,
                jwks_sha256=hashlib.sha256(jwks).hexdigest(),
            )
            result = probe_candidate_archive(archive_path, summary.receipt, tokens)
            result["wheel_count"] = summary.wheel_count
            result["zip_bytes"] = summary.zip_bytes
            return result
    except ValueError:
        raise
    except Exception:
        raise ValueError("retained_dev_runtime_arm_probe_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.wheel_dir)
    except Exception as exc:
        category = str(exc) if str(exc) in _SAFE_FAILURES else "retained_dev_runtime_arm_probe_failed"
        print(json.dumps({"success": False, "category": category}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
