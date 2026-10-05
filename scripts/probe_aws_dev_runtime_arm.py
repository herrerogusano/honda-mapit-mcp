"""Run the synthetic dev runtime ZIP in the pinned ARM Lambda image offline.

The probe builds a fresh fixed-source archive from local wheels, generates a
one-run RSA/JWKS fixture, and sends synthetic access tokens only over the
container's stdin. It does not call AWS or expose token, key, path, or response
content in its output.
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
import time
import uuid
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mapit.aws_dev_runtime import CognitoDevPolicy, cognito_dev_policy
from scripts import build_aws_dev_runtime as builder

IMAGE = "public.ecr.aws/lambda/python@sha256:69b91b6e0b637c459f80bc103c2e566be76cbeb934f32bf2d8c14e028ce57719"
_MAX_DOCKER_SECONDS = 240
_MAX_STDOUT_BYTES = 8 * 1024
_CHECK_NAMES = (
    "initialize",
    "tools_list_exactly_ten",
    "tool_calls_all_succeeded",
    "warm_repeat",
    "missing_auth_401",
    "unknown_kid_401",
    "wrong_audience_401",
    "wrong_scope_403",
    "prod_isolation_503",
    "missing_config_503",
)
_POOL_ID = "eu-west-1_A1b2C3d4E"
_API_ID = "a1b2c3d4e5"
_CLIENT_ID = "SyntheticCognitoClient012345"
_OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
_KID = "offline-arm-probe-key"
_OWNER_LABEL = "com.honda-mapit.arm-probe.owner"
_RUN_LABEL = "com.honda-mapit.arm-probe.run"
_CONTAINER_NAME_PREFIX = "honda-mapit-arm-probe-"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_FAILURES = frozenset({
    "wheel_directory_invalid",
    "temporary_directory_invalid",
    "local_docker_context_unavailable",
    "arm_probe_output_invalid",
    "arm_probe_execution_failed",
    "cleanup_unverified",
    "runtime_arm_probe_failed",
})

_CONTAINER_PROBE = r'''import json,os,sys,tempfile,time,zipfile
from pathlib import Path
p=json.loads(sys.stdin.read()); root=Path(tempfile.mkdtemp(prefix="arm-probe-")); zipfile.ZipFile("/probe/runtime.zip").extractall(root); sys.path.insert(0,str(root))
from mapit import aws_dev_entrypoint as ep
now=time.time()
if not isinstance(now,(int,float)) or isinstance(now,bool) or not 0 < now < 253402300799: raise SystemExit(3)
os.environ.update({"MAPIT_MCP_ENV":"dev","AWS_REGION":"eu-west-1","MAPIT_COGNITO_USER_POOL_ID":"eu-west-1_A1b2C3d4E","MAPIT_API_ID":"a1b2c3d4e5","MAPIT_COGNITO_CLIENT_ID":"SyntheticCognitoClient012345","MAPIT_OWNER_SUBJECT":"18d8ce2b-8f10-4d72-b80f-ea635b4c6189","MAPIT_COGNITO_JWKS_SHA256":p["snapshot_sha256"],"MAPIT_DEV_EXECUTION_START_EPOCH":str(int(now)-1),"MAPIT_DEV_EXECUTION_END_EPOCH":str(int(now)+299)})
class C:
 def get_remaining_time_in_millis(self): return 30000
def rpc(method,params=None,ident=1): return json.dumps({"jsonrpc":"2.0","id":ident,"method":method,"params":params or {}},separators=(",",":"))
def invoke(token,body):
 headers={"host":"a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com","content-type":"application/json","content-length":str(len(body.encode("utf-8"))),"accept":"application/json, text/event-stream"}
 if token is not None: headers["authorization"]="Bearer "+token
 event={"version":"2.0","rawPath":"/mcp","rawQueryString":"","headers":headers,"requestContext":{"stage":"$default","http":{"method":"POST","path":"/mcp"}},"body":body,"isBase64Encoded":False}
 return ep.handler(event,C())
def parsed(response):
 try: return json.loads(response.get("body",""))
 except Exception: return {}
out={}
token=p["tokens"]["valid"]
response=invoke(token,rpc("initialize",{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"offline-arm-probe","version":"1"}}))
initialized=parsed(response)
initialize_result=initialized.get("result",{})
out["initialize"]=response.get("statusCode")==200 and initialized.get("jsonrpc")=="2.0" and "error" not in initialized and isinstance(initialize_result,dict) and initialize_result.get("protocolVersion")=="2025-03-26" and isinstance(initialize_result.get("serverInfo"),dict)
response=invoke(token,rpc("tools/list")); document=parsed(response)
names=[item.get("name") for item in document.get("result",{}).get("tools",[])]
expected=["get_vehicle_status","get_vehicle_details","list_routes","get_route_detail","get_distance","compare_distance_periods","get_route_statistics","get_distance_breakdown","get_route_extremes","compare_route_periods"]
out["tools_list_exactly_ten"]=len(names)==10 and set(names)==set(expected)
rng={"from_time":"2026-01-01","to_time":"2026-02-01"}; period={"period_a":rng,"period_b":{"from_time":"2026-02-01","to_time":"2026-03-01"}}
calls=[("get_vehicle_status",{}),("get_vehicle_details",{}),("list_routes",rng),("get_route_detail",{"route_id":"synthetic-route"}),("get_distance",rng),("compare_distance_periods",period),("get_route_statistics",rng),("get_distance_breakdown",dict(rng,group_by="day")),("get_route_extremes",rng),("compare_route_periods",period)]
successes=0
for index,(name,args) in enumerate(calls,1):
 response=invoke(token,rpc("tools/call",{"name":name,"arguments":args},index)); result=parsed(response).get("result",{})
 successes += response.get("statusCode")==200 and result.get("isError") is False
out["tool_calls_all_succeeded"]=successes==10
first=invoke(token,rpc("tools/list")); second=invoke(token,rpc("tools/list"))
first_names=[item.get("name") for item in parsed(first).get("result",{}).get("tools",[])]
second_names=[item.get("name") for item in parsed(second).get("result",{}).get("tools",[])]
out["warm_repeat"]=first.get("statusCode")==200 and second.get("statusCode")==200 and len(first_names)==10 and len(second_names)==10 and set(first_names)==set(second_names)==set(expected)
out["missing_auth_401"]=invoke(None,rpc("tools/list")).get("statusCode")==401
out["unknown_kid_401"]=invoke(p["tokens"]["unknown_kid"],rpc("tools/list")).get("statusCode")==401
out["wrong_audience_401"]=invoke(p["tokens"]["wrong_audience"],rpc("tools/list")).get("statusCode")==401
out["wrong_scope_403"]=invoke(p["tokens"]["wrong_scope"],rpc("tools/list")).get("statusCode")==403
def clear_cache():
 ep._CACHED_RUNTIME=None; ep._CACHED_JWKS_SHA256=None; ep._CACHED_WINDOW=None
os.environ["MAPIT_MCP_ENV"]="prod"; clear_cache(); out["prod_isolation_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
os.environ["MAPIT_MCP_ENV"]="dev"; os.environ.pop("MAPIT_API_ID",None); clear_cache(); out["missing_config_503"]=invoke(token,rpc("tools/list")).get("statusCode")==503
print(json.dumps(out,sort_keys=True,separators=(",",":")))
sys.exit(0 if all(out.values()) else 2)
'''


class ProbeError(ValueError):
    """Fixed safe probe failure category."""


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sign_token(private_key: rsa.RSAPrivateKey, policy: CognitoDevPolicy, claims: dict[str, Any], kid: str) -> str:
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    head = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii"))
    body = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("ascii"))
    signing_input = f"{head}.{body}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64url(signature)}"


def _synthetic_snapshot_and_tokens(policy: CognitoDevPolicy, now: int) -> tuple[bytes, dict[str, str]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    document = {
        "keys": [{
            "kty": "RSA",
            "kid": _KID,
            "use": "sig",
            "alg": "RS256",
            "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
        }]
    }
    snapshot = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

    def signed(kid: str = _KID, **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": policy.issuer_url,
            "aud": policy.audience,
            "sub": policy.owner_subject,
            "client_id": policy.client_id,
            "token_use": "access",
            "iat": now,
            "exp": now + 240,
            "scope": policy.required_scope,
        }
        claims.update(overrides)
        return _sign_token(private_key, policy, claims, kid)

    tokens = {
        "valid": signed(),
        "unknown_kid": signed("unknown-offline-key"),
        "wrong_audience": signed(aud="https://wrong.invalid/mcp"),
        "wrong_scope": signed(scope="https://wrong.invalid/mcp/use"),
    }
    # private_key remains a local object only; it is neither returned nor serialized.
    return snapshot, tokens


def _docker_command(archive: Path, *, context: str, container_name: str, run_id: str, cid_file: Path) -> list[str]:
    return [
        "docker", "--context", context, "run", "--rm", "--pull=never", "-i",
        "--name", container_name, "--label", f"{_OWNER_LABEL}=honda-mapit-mcp",
        "--label", f"{_RUN_LABEL}={run_id}", "--cidfile", str(cid_file),
        "--platform", "linux/arm64", "--network", "none", "--mount",
        f"type=bind,source={archive},target=/probe/runtime.zip,readonly",
        "--entrypoint", "python3", IMAGE, "-c", _CONTAINER_PROBE,
    ]


def _docker_context(runner: Any | None = None) -> str:
    selected_runner = runner or subprocess.run
    try:
        selected = selected_runner(
            ["docker", "context", "show"], capture_output=True, text=True, check=False, timeout=5
        )
        context = selected.stdout.strip()
        if selected.returncode != 0 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", context):
            raise ProbeError("local_docker_context_unavailable")
        endpoint_result = selected_runner(
            ["docker", "context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeError("local_docker_context_unavailable") from None
    endpoint = endpoint_result.stdout.strip().casefold()
    local_endpoint = endpoint.startswith("unix://") or endpoint.startswith("npipe:////./pipe/")
    if endpoint_result.returncode != 0 or not local_endpoint:
        raise ProbeError("local_docker_context_unavailable")
    return context


def _docker_call(context: str, arguments: list[str], *, runner: Any | None = None, timeout: float = 5):
    selected_runner = runner or subprocess.run
    return selected_runner(
        ["docker", "--context", context, *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _bounded_cid_file(cid_file: Path) -> str | None:
    try:
        if cid_file.is_symlink() or cid_file.stat().st_size > 66:
            return None
        with cid_file.open("rb") as source:
            raw = source.read(67)
    except FileNotFoundError:
        return ""
    except OSError:
        return None
    if len(raw) > 66:
        return None
    try:
        value = raw.decode("ascii").strip()
    except UnicodeError:
        return None
    return value if _HEX_64.fullmatch(value) else None


def _list_named_container(context: str, container_name: str, *, runner: Any | None = None):
    return _docker_call(
        context,
        ["container", "ls", "--all", "--no-trunc", "--filter", f"name=^/{container_name}$", "--format", "{{.ID}}"],
        runner=runner,
        timeout=5,
    )


def _cleanup_owned_container(
    context: str,
    container_name: str,
    run_id: str,
    cid_file: Path,
    *,
    runner: Any | None = None,
) -> bool:
    """Remove only the exact named/labelled run and verify absence by exact name."""
    try:
        listing = _list_named_container(context, container_name, runner=runner)
    except Exception:
        return False
    if listing.returncode != 0:
        return False
    ids = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    if not ids:
        return True
    if len(ids) != 1 or not _HEX_64.fullmatch(ids[0]):
        return False
    cid = ids[0]
    cid_value = _bounded_cid_file(cid_file)
    if cid_value is None or (cid_value and cid_value != cid):
        return False
    inspect_format = f"{{{{.Id}}}}|{{{{index .Config.Labels \"{_OWNER_LABEL}\"}}}}|{{{{index .Config.Labels \"{_RUN_LABEL}\"}}}}"
    try:
        inspected = _docker_call(
            context,
            ["container", "inspect", "--format", inspect_format, container_name],
            runner=runner,
            timeout=5,
        )
    except Exception:
        return False
    fields = inspected.stdout.strip().split("|")
    if (
        inspected.returncode != 0
        or len(fields) != 3
        or fields[0] != cid
        or fields[1] != "honda-mapit-mcp"
        or fields[2] != run_id
    ):
        return False
    try:
        _docker_call(context, ["container", "rm", "--force", cid], runner=runner, timeout=10)
        final = _list_named_container(context, container_name, runner=runner)
    except Exception:
        return False
    return final.returncode == 0 and not any(line.strip() for line in final.stdout.splitlines())


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate result key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid result constant")


def _parse_check_matrix(stdout: str) -> dict[str, bool]:
    if not isinstance(stdout, str) or not stdout or len(stdout.encode("utf-8", errors="ignore")) > _MAX_STDOUT_BYTES:
        raise ProbeError("arm_probe_output_invalid")
    try:
        value = json.loads(stdout, object_pairs_hook=_reject_duplicate_members, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError):
        raise ProbeError("arm_probe_output_invalid") from None
    if not isinstance(value, dict) or set(value) != set(_CHECK_NAMES):
        raise ProbeError("arm_probe_output_invalid")
    if any(type(value[name]) is not bool for name in _CHECK_NAMES):
        raise ProbeError("arm_probe_output_invalid")
    return value


def _run_probe(wheel_dir: Path) -> dict[str, Any]:
    """Build and test one synthetic runtime archive; return only fixed metadata."""
    if not isinstance(wheel_dir, Path):
        raise ProbeError("wheel_directory_invalid")
    try:
        repo = builder._repo_root()
        wheel_root = builder._validate_external_wheel_dir(wheel_dir, repo)
    except Exception:
        raise ProbeError("wheel_directory_invalid") from None
    policy = cognito_dev_policy(
        user_pool_id=_POOL_ID,
        api_id=_API_ID,
        client_id=_CLIENT_ID,
        owner_subject=_OWNER,
    )
    now = int(time.time())
    snapshot, tokens = _synthetic_snapshot_and_tokens(policy, now)
    try:
        with tempfile.TemporaryDirectory(prefix="honda-mapit-arm-probe-") as temp_name:
            temp_root = Path(temp_name).resolve(strict=True)
            builder._outside_repo_and_onedrive(temp_root, repo, "temporary_directory_invalid")
            context = _docker_context()
            snapshot_path = temp_root / "synthetic-public-jwks.json"
            archive_path = temp_root / "runtime.zip"
            cid_file = temp_root / "container.cid"
            snapshot_path.write_bytes(snapshot)
            summary = builder.build_runtime_archive(wheel_root, snapshot_path, archive_path, policy)
            run_id = uuid.uuid4().hex
            container_name = f"{_CONTAINER_NAME_PREFIX}{run_id}"
            payload = json.dumps(
                {"snapshot_sha256": hashlib.sha256(snapshot).hexdigest(), "tokens": tokens},
                sort_keys=True,
                separators=(",", ":"),
            )
            process = None
            timeout = False
            execution_error: BaseException | None = None
            try:
                process = subprocess.run(
                    _docker_command(
                        archive_path,
                        context=context,
                        container_name=container_name,
                        run_id=run_id,
                        cid_file=cid_file,
                    ),
                    input=payload,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=_MAX_DOCKER_SECONDS,
                )
            except subprocess.TimeoutExpired:
                timeout = True
            except BaseException as exc:
                execution_error = exc
            try:
                cleanup_verified = _cleanup_owned_container(context, container_name, run_id, cid_file)
            except BaseException:
                cleanup_verified = False
            if not cleanup_verified:
                raise ProbeError("cleanup_unverified")
            if timeout or process is None:
                raise ProbeError("arm_probe_execution_failed")
            if execution_error is not None:
                if isinstance(execution_error, OSError):
                    raise ProbeError("arm_probe_execution_failed") from None
                raise execution_error
            stdout = process.stdout
            # Never forward stdout/stderr or any token-bearing process input.
            checks = _parse_check_matrix(stdout) if process.returncode in (0, 2) else None
            if checks is None:
                raise ProbeError("arm_probe_execution_failed")
            success = process.returncode == 0 and all(checks.values())
            return {
                "success": success,
                "category": "arm_probe_passed" if success else "arm_probe_failed",
                "zip_bytes": summary.zip_bytes,
                "zip_sha256": summary.sha256,
                "wheel_count": summary.wheel_count,
                "archive_entries": summary.archive_entries,
                "source_modules": summary.source_modules,
                "public_key_count": summary.public_key_count,
                "checks": checks,
            }
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("runtime_arm_probe_failed") from None


def run_probe(wheel_dir: Path) -> dict[str, Any]:
    """Public safe wrapper: unexpected setup/clock/crypto errors stay closed."""
    try:
        return _run_probe(wheel_dir)
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("runtime_arm_probe_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.wheel_dir)
    except ProbeError as exc:
        category = str(exc) if str(exc) in _SAFE_FAILURES else "runtime_arm_probe_failed"
        print(json.dumps({"success": False, "category": category}, separators=(",", ":")))
        return 1
    except Exception:
        print(json.dumps({"success": False, "category": "runtime_arm_probe_failed"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
