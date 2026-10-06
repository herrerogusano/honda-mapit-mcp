"""Bounded offline ARM probe for the synthetic two-tenant DEV archive.

The probe packages the existing source with the local, hash-locked 28-wheel
platform set and runs it in the pinned Lambda ARM image with Docker networking
disabled and a 256 MiB memory limit.  The container injects an in-memory fake
DynamoDB reader; no AWS client, credential, MAPIT session, or private binding
is used.  Output is only fixed booleans/categories.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mapit.aws_dev_runtime import cognito_dev_policy
from scripts import build_aws_dev_multiuser_archive as archive_builder
from scripts import build_aws_dev_runtime as runtime_builder
from scripts import probe_aws_dev_runtime_arm as docker_helpers

IMAGE = docker_helpers.IMAGE
REGION = "eu-west-1"
ACCOUNT_ID = "123456789012"
POOL_ID = "eu-west-1_A1b2C3d4E"
API_ID = "a1b2c3d4e5"
CLIENT_ID = "SyntheticDevMultiuserClient"
SUBJECTS = (
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
)
TENANT_KEYS = ("tenant-" + "1" * 64, "tenant-" + "2" * 64)
SOURCE_SHA = "a" * 40
KID = "offline-dev-multiuser-arm-key"
START = 1_900_000_000
END = START + 300
CHECKS = (
    "archive_import", "manifest_valid", "jwks_valid", "runtime_imported", "runtime_composed",
    "tools_list_exactly_ten",
    "tenant_a_success", "tenant_b_success", "revocation_denied",
)
SAFE_FAILURES = frozenset({
    "wheel_directory_invalid", "temporary_directory_invalid", "local_docker_context_unavailable",
    "arm_probe_output_invalid", "arm_probe_execution_failed", "cleanup_unverified",
    "multiuser_arm_probe_failed",
})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProbeError(ValueError):
    """Fixed safe probe category."""


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _fixture() -> tuple[bytes, bytes, dict[str, str], dict[str, Any]]:
    """Build only synthetic manifest/JWKS/token material in memory."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = json.dumps({"keys": [{
        "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }]}, sort_keys=True, separators=(",", ":")).encode("ascii")
    jwks_sha = hashlib.sha256(jwks).hexdigest()
    manifest = {
        "schema": 1, "builder": "build_retained_dev_multiuser_archive",
        "environment": "dev", "synthetic": True, "source_sha": SOURCE_SHA,
        "api_id": API_ID, "user_pool_id": POOL_ID, "client_id": CLIENT_ID,
        "jwks_sha256": jwks_sha,
        "table_arn": f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/honda-mapit-mcp-dev-tenants",
        "tenants": [
            {"key": TENANT_KEYS[0], "subject": SUBJECTS[0], "label": "synthetic-A"},
            {"key": TENANT_KEYS[1], "subject": SUBJECTS[1], "label": "synthetic-B"},
        ],
    }
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    policy = cognito_dev_policy(user_pool_id=POOL_ID, api_id=API_ID,
                                client_id=CLIENT_ID, owner_subject=SUBJECTS[0])

    def sign(subject: str) -> str:
        claims = {
            "iss": policy.issuer_url, "aud": policy.audience, "sub": subject,
            "client_id": CLIENT_ID, "token_use": "access", "iat": START + 30,
            "exp": END - 30, "scope": policy.required_scope,
        }
        head = _b64url(json.dumps({"alg": "RS256", "kid": KID, "typ": "JWT"},
                                  sort_keys=True, separators=(",", ":")).encode("ascii"))
        body = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("ascii"))
        signature = private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64url(signature)}"

    tokens = {"a": sign(SUBJECTS[0]), "b": sign(SUBJECTS[1])}
    return manifest_raw, jwks, tokens, {"manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                                         "jwks_sha256": jwks_sha, "zip_sha256": ""}


_CONTAINER_PROBE = r'''import hashlib,json,os,sys,tempfile,zipfile
from pathlib import Path
p=json.loads(sys.stdin.read(65536)); out={key:False for key in p["checks"]}
try:
 raw=Path("/probe/runtime.zip").read_bytes(); root=Path(tempfile.mkdtemp(prefix="dev-multiuser-arm-"))
 with zipfile.ZipFile(__import__("io").BytesIO(raw)) as z:
  z.extractall(root); out["archive_import"]=True
  manifest_raw=z.read("mapit/dev-multiuser.manifest.json"); jwks_raw=z.read("mapit/dev-multiuser.jwks.json")
  out["manifest_valid"]=hashlib.sha256(manifest_raw).hexdigest()==p["manifest_sha256"]
  out["jwks_valid"]=hashlib.sha256(jwks_raw).hexdigest()==p["jwks_sha256"]
 sys.path.insert(0,str(root)); import mapit.aws_dev_multiuser_entrypoint as ep; out["runtime_imported"]=True
 os.environ.update({"MAPIT_MCP_ENV":"dev","MAPIT_DEV_MULTIUSER_MODE":"synthetic","AWS_REGION":"eu-west-1",
  "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256":p["manifest_sha256"],"MAPIT_DEV_EXPECTED_ACCOUNT_ID":p["account_id"],
  "MAPIT_DEV_EXECUTION_START_EPOCH":str(p["start"]),"MAPIT_DEV_EXECUTION_END_EPOCH":str(p["end"]),
  "MAPIT_SOURCE_SHA256":p["source_sha"],"MAPIT_COGNITO_JWKS_SHA256":p["jwks_sha256"],
  "MAPIT_COGNITO_USER_POOL_ID":p["user_pool_id"],"MAPIT_COGNITO_CLIENT_ID":p["client_id"],
  "MAPIT_OBSERVED_API_ID":p["api_id"]})
 ep.time.time=lambda:float(p["now"])
 class Reader:
  def __init__(self): self.status={p["keys"]["a"]:"active",p["keys"]["b"]:"active"}
  def get_item(self,**request):
   key=request["Key"]["key"]["S"]; status=self.status.get(key)
   result={"ResponseMetadata":{"HTTPStatusCode":200}}
   if status is not None: result["Item"]={"key":{"S":key},"status":{"S":status},"revision":{"N":"1"}}
   return result
 reader=Reader(); ep._CACHED=ep.compose_runtime(manifest_raw,jwks_raw,manifest_digest=p["manifest_sha256"],account_id=p["account_id"],dynamodb_reader=reader)
 ep._BINDING=(p["manifest_sha256"],p["account_id"],str(p["start"]),str(p["end"]),p["source_sha"],p["jwks_sha256"],p["user_pool_id"],p["client_id"],p["api_id"])
 out["runtime_composed"]=True
 class C:
  def get_remaining_time_in_millis(self): return 30000
 def rpc(method,params=None,ident=1): return json.dumps({"jsonrpc":"2.0","id":ident,"method":method,"params":params or {}},separators=(",",":"))
 def invoke(token,body):
  headers={"host":p["api_id"]+".execute-api.eu-west-1.amazonaws.com","content-type":"application/json","content-length":str(len(body.encode())),"accept":"application/json, text/event-stream","authorization":"Bearer "+token}
  event={"version":"2.0","rawPath":"/mcp","rawQueryString":"","headers":headers,"requestContext":{"stage":"$default","http":{"method":"POST","path":"/mcp"}},"body":body,"isBase64Encoded":False}
  return ep.handler(event,C())
 def parsed(response):
  try:return json.loads(response.get("body",""))
  except Exception:return {}
 def call(token,method,params=None,ident=1): return invoke(token,rpc(method,params,ident))
 listed=parsed(call(p["tokens"]["a"],"tools/list")); names=[x.get("name") for x in listed.get("result",{}).get("tools",[])]
 expected=["get_vehicle_status","get_vehicle_details","list_routes","get_route_detail","get_distance","compare_distance_periods","get_route_statistics","get_distance_breakdown","get_route_extremes","compare_route_periods"]
 out["tools_list_exactly_ten"]=len(names)==10 and set(names)==set(expected)
 a=parsed(call(p["tokens"]["a"],"tools/call",{"name":"get_vehicle_status","arguments":{}},2)); out["tenant_a_success"]=a.get("result",{}).get("isError") is False
 b=parsed(call(p["tokens"]["b"],"tools/call",{"name":"get_vehicle_status","arguments":{}},3)); out["tenant_b_success"]=b.get("result",{}).get("isError") is False
 reader.status[p["keys"]["a"]]="revoked"
 denied=parsed(call(p["tokens"]["a"],"tools/call",{"name":"get_vehicle_status","arguments":{}},4)); out["revocation_denied"]=denied.get("result",{}).get("isError") is True
except BaseException: pass
print(json.dumps({"checks":out},sort_keys=True,separators=(",",":"))); sys.exit(0 if all(out.values()) else 2)
'''


def _run_bounded(command: list[str], payload: str, *, timeout: float = 240.0) -> tuple[int, str]:
    """Run the child with bounded pipes and a timeout that includes stdin."""
    process = None
    overflow = threading.Event()
    writer_failed = threading.Event()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}

    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, bufsize=0)
    except Exception:
        raise ProbeError("arm_probe_execution_failed") from None

    def kill_child() -> None:
        try:
            if process is not None and process.poll() is None:
                process.kill()
        except Exception:
            pass

    def drain(name: str, stream: Any) -> None:
        try:
            while True:
                remaining = 8193 - len(buffers[name])
                chunk = stream.read(min(4096, max(1, remaining)))
                if not chunk:
                    return
                if len(buffers[name]) + len(chunk) > 8192:
                    overflow.set()
                    kill_child()
                    return
                buffers[name].extend(chunk)
        except Exception:
            overflow.set()
            kill_child()

    def write_input() -> None:
        try:
            assert process is not None and process.stdin is not None
            process.stdin.write(payload.encode("utf-8", errors="strict"))
            process.stdin.flush()
        except Exception:
            writer_failed.set()
        finally:
            try:
                if process is not None and process.stdin is not None:
                    process.stdin.close()
            except Exception:
                pass

    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    readers = [threading.Thread(target=drain, args=(name, stream), daemon=True)
               for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for reader in readers:
        reader.start()
    writer = threading.Thread(target=write_input, daemon=True)
    writer.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_child()
        try:
            process.wait(timeout=2)
        except Exception:
            pass
    except Exception:
        kill_child()
        try:
            process.wait(timeout=2)
        except Exception:
            pass
        raise ProbeError("arm_probe_execution_failed") from None
    writer.join(timeout=2)
    for reader in readers:
        reader.join(timeout=2)
    if timed_out:
        raise ProbeError("arm_probe_execution_failed") from None
    if overflow.is_set():
        raise ProbeError("arm_probe_output_invalid") from None
    if writer.is_alive() or any(reader.is_alive() for reader in readers) or writer_failed.is_set():
        raise ProbeError("arm_probe_execution_failed") from None
    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
        return_code = process.returncode
    except UnicodeError:
        raise ProbeError("arm_probe_output_invalid") from None
    except Exception:
        raise ProbeError("arm_probe_output_invalid") from None
    if type(return_code) is not int:
        raise ProbeError("arm_probe_execution_failed") from None
    return return_code, stdout


def _parse_output(stdout: str) -> dict[str, Any]:
    try:
        value = json.loads(stdout)
        checks = value.get("checks") if isinstance(value, dict) else None
        if set(value) != {"checks"} or not isinstance(checks, dict) or set(checks) != set(CHECKS):
            raise ValueError
        if any(type(checks[key]) is not bool for key in CHECKS):
            raise ValueError
        return checks
    except Exception:
        raise ProbeError("arm_probe_output_invalid") from None


def _docker_command(archive: Path, *, context: str, name: str, cidfile: Path, run_id: str) -> list[str]:
    return ["docker", "--context", context, "run", "--rm", "--pull=never", "-i",
            "--platform", "linux/arm64", "--network", "none", "--memory", "256m",
            "--name", name, "--label", "com.honda-mapit.dev-multiuser-arm=1",
            "--label", f"{docker_helpers._OWNER_LABEL}=honda-mapit-mcp",
            "--label", f"{docker_helpers._RUN_LABEL}={run_id}",
            "--cidfile", str(cidfile), "--mount", f"type=bind,source={archive.resolve()},target=/probe/runtime.zip,readonly",
            "--entrypoint", "python3", IMAGE, "-c", _CONTAINER_PROBE]


def probe_candidate_archive(archive: Path, *, context: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(archive, Path) or not archive.is_file():
        raise ProbeError("temporary_directory_invalid")
    run_id = uuid.uuid4().hex
    name = f"honda-mapit-dev-multiuser-arm-{run_id[:12]}"
    with tempfile.TemporaryDirectory(prefix="honda-mapit-dev-multiuser-arm-") as scratch:
        cidfile = Path(scratch) / "cid"
        command = _docker_command(archive, context=context, name=name, cidfile=cidfile, run_id=run_id)
        try:
            status, stdout = _run_bounded(command, json.dumps(payload, separators=(",", ":")))
            checks = _parse_output(stdout)
        finally:
            # The helper applies ownership labels and never removes an unrelated container.
            try:
                cleaned = docker_helpers._cleanup_owned_container(context, name, run_id, cidfile)
            except Exception:
                cleaned = False
        if not cleaned:
            raise ProbeError("cleanup_unverified")
    return {"success": status == 0 and all(checks.values()), "category": "multiuser_arm_probe_passed" if status == 0 and all(checks.values()) else "multiuser_arm_probe_failed", "checks": checks}


def run_probe(wheel_dir: Path, *, docker_context: str | None = None) -> dict[str, Any]:
    if not isinstance(wheel_dir, Path):
        raise ProbeError("wheel_directory_invalid")
    repo = runtime_builder._repo_root()
    wheel_root = runtime_builder._validate_external_wheel_dir(wheel_dir, repo)
    manifest_raw, jwks_raw, tokens, hashes_value = _fixture()
    with tempfile.TemporaryDirectory(prefix="honda-mapit-dev-multiuser-arm-") as scratch:
        root = Path(scratch).resolve(strict=True)
        runtime_builder._outside_repo_and_onedrive(root, repo, "temporary_directory_invalid")
        manifest_path, jwks_path, archive_path = root / "manifest.json", root / "jwks.json", root / "runtime.zip"
        manifest_path.write_bytes(manifest_raw); jwks_path.write_bytes(jwks_raw)
        summary = archive_builder.build_dev_multiuser_archive(wheel_root, manifest_path, jwks_path, archive_path, account_id=ACCOUNT_ID)
        context = docker_helpers._docker_context()
        if docker_context is not None and docker_context != context:
            raise ProbeError("local_docker_context_unavailable")
        payload = {"checks": list(CHECKS), "manifest_sha256": hashes_value["manifest_sha256"], "jwks_sha256": hashes_value["jwks_sha256"], "source_sha": SOURCE_SHA, "user_pool_id": POOL_ID, "client_id": CLIENT_ID, "account_id": ACCOUNT_ID, "api_id": API_ID, "start": START, "end": END, "now": START + 60, "keys": {"a": TENANT_KEYS[0], "b": TENANT_KEYS[1]}, "tokens": tokens}
        result = probe_candidate_archive(archive_path, context=context, payload=payload)
        result["wheel_count"] = summary.wheel_count
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.wheel_dir)
    except Exception as exc:
        category = str(exc) if str(exc) in SAFE_FAILURES else "multiuser_arm_probe_failed"
        print(json.dumps({"success": False, "category": category}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
