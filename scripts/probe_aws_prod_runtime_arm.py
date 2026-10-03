"""Offline synthetic ARM smoke test for the exact production runtime ZIP.

The probe builds from the locally pinned wheels and sends only a synthetic JWT
and public JWKS digest to the pinned Lambda ARM image. SSM, Cognito and MAPIT
are faked inside the container; Docker networking is disabled. No AWS client
or credential provider is contacted.
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
import time
import uuid
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.config import MapitConfig
from scripts import build_aws_dev_runtime as dev_builder
from scripts import build_aws_prod_runtime as prod_builder
from scripts import probe_aws_dev_runtime_arm as docker_helpers

IMAGE = docker_helpers.IMAGE
_MAX_DOCKER_SECONDS = 240
_MAX_OUTPUT = 8192
_POOL = "eu-west-1_A1b2C3d4E"
_API = "a1b2c3d4e5"
_CLIENT = "SyntheticProdClient012345"
_OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
_ACCOUNT = "123456789012"
_IDENTITY = "eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
_KID = "offline-prod-arm-probe-key"
_NAME_PREFIX = "honda-mapit-prod-arm-probe-"
_CHECKS = (
    "initialize", "tools_list_exactly_ten", "tool_calls_all_succeeded", "warm_repeat",
    "missing_auth_401", "unknown_kid_401", "wrong_audience_401", "wrong_scope_403",
    "dev_isolation_503", "missing_config_503", "lazy_ssm_per_invocation", "token_signature_claims_valid",
)
_GEOGRAPHY_CHECKS = (
    "geographic_summary_counts_and_km", "summer_summary_local_boundaries",
    "invalid_area_before_ssm", "invalid_year_before_ssm", "geometry_asset_digest",
    "geometry_engine_bounded_memory", "geometry_engine_repeat_classification",
    "amb_asset_digest", "amb_union_and_barcelona_summaries", "amb_registry_cache_bounded",
)
_SAFE_FAILURES = frozenset({
    "wheel_directory_invalid", "temporary_directory_invalid", "local_docker_context_unavailable",
    "arm_probe_output_invalid", "arm_probe_execution_failed", "cleanup_unverified",
    "production_runtime_arm_probe_failed",
})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_CONTAINER_PROBE = r'''import base64,hashlib,json,os,sys,tempfile,zipfile
from pathlib import Path
p=json.loads(sys.stdin.read()); root=Path(tempfile.mkdtemp(prefix="prod-arm-probe-")); zipfile.ZipFile("/probe/runtime.zip").extractall(root); sys.path.insert(0,str(root))
from mapit import aws_prod_entrypoint as ep
manifest_raw=(root/"mapit"/ep.MANIFEST_FILENAME).read_bytes(); manifest=json.loads(manifest_raw); now=__import__("time").time()
os.environ.update({"AWS_LAMBDA_FUNCTION_NAME":ep.FUNCTION_NAME,"AWS_REGION":"eu-west-1","MAPIT_MCP_ENV":"prod","MAPIT_PROD_MANIFEST_SHA256":hashlib.sha256(manifest_raw).hexdigest(),"AWS_ACCESS_KEY_ID":"synthetic-access-key","AWS_SECRET_ACCESS_KEY":"synthetic-secret-key","AWS_SESSION_TOKEN":"synthetic-session-token"})
class Context:
 def get_remaining_time_in_millis(self): return 30000
class SSM:
 def __init__(self): self.calls=0
 def get_parameter(self,**kw):
  self.calls+=1
  assert kw=={"Name":"/honda-mapit-mcp/prod/mapit-refresh-token:1","WithDecryption":True}
  return {"ResponseMetadata":{"HTTPStatusCode":200},"Parameter":{"Name":"/honda-mapit-mcp/prod/mapit-refresh-token","ARN":"arn:aws:ssm:eu-west-1:123456789012:parameter/honda-mapit-mcp/prod/mapit-refresh-token","Type":"SecureString","Version":1,"DataType":"text","Value":"synthetic-refresh-token-only"}}
ssm=SSM(); ep._ssm_client_factory=lambda:ssm
class FakeTransport:
 def __init__(self,config,*,deadline): self.config=config; self.calls=0
 def cognito_json(self,url,headers,payload):
  target=headers["X-Amz-Target"]
  if target.endswith("InitiateAuth"): return {"AuthenticationResult":{"IdToken":"x."+base64.urlsafe_b64encode(json.dumps({"exp":int(now)+3600}).encode()).decode().rstrip("=")+".x","AccessToken":"synthetic-cognito-access","ExpiresIn":3600}}
  if target.endswith("GetId"): return {"IdentityId":self.config.identity_pool_id}
  if target.endswith("GetCredentialsForIdentity"): return {"Credentials":{"AccessKeyId":"synthetic","SecretKey":"synthetic","SessionToken":"synthetic","Expiration":int(now)+3600}}
  raise AssertionError("unexpected target")
 def mapit_request(self,method,url,headers):
  self.calls+=1
  from urllib.parse import urlsplit,parse_qs
  path=urlsplit(url).path
  vehicle={"id":"synthetic-vehicle","km":1234,"product":"synthetic","device":{"state":{"status":"AT_REST","speed":0,"battery":80,"voltage":12,"lastTs":int(now),"lastCoordTs":int(now),"lat":1,"lng":2,"location":"synthetic","hdop":1}}}
  route={"id":"synthetic-route","startedAt":"2026-01-15T10:00:00Z","endedAt":"2026-01-15T10:30:00Z","distance":5000,"avgSpeed":20,"maxSpeed":40,"complete":True,"geoJSON":{"type":"FeatureCollection","features":[]}}
  if path=="/v1/account-summary": value={"vehicles":[vehicle]}
  elif path=="/v1/vehicles/synthetic-vehicle": value={"model":"Synthetic Model","registrationNumber":"SYNTH","vin":"SYNTH","km":1234,"products":["synthetic"]}
  elif path=="/v1/routes":
   query=parse_qs(urlsplit(url).query)
   if manifest.get("geographic_queries") is True and query.get("from",[""])[0]>="2026-05":
    def geo_route(ident,positions):
     return dict(route,id=ident,startedAt="2026-06-15T10:00:00Z",endedAt="2026-06-15T10:30:00Z",geoJSON={"type":"FeatureCollection","features":[{"type":"Feature","properties":{"inferred":False},"geometry":{"type":"LineString","coordinates":positions}}]})
    rows=[geo_route("synthetic-menorca",[[4.12,39.96],[4.121,39.961]]),geo_route("synthetic-outside",[[2.16,41.39],[2.17,41.40]])]
    value={"data":rows if query.get("from",[""])[0]<="2026-06-15T10:00:00Z"<query.get("to",[""])[0] else []}
   else: value={"data":[route]}
  elif path=="/v1/vehicles/synthetic-vehicle/routes/synthetic-route": value=route
  else: raise AssertionError("unexpected path")
  return json.dumps(value,separators=(",",":")).encode()
ep.CloudDirectTransport=FakeTransport
def b64u(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def rpc(method,params=None,ident=1): return json.dumps({"jsonrpc":"2.0","id":ident,"method":method,"params":params or {}},separators=(",",":"))
def invoke(token,body):
 policy=ep._parse_manifest(manifest_raw)["_validated_policy"]
 headers={"host":policy.api_host,"content-type":"application/json","content-length":str(len(body.encode())),"accept":"application/json, text/event-stream"}
 if token is not None: headers["authorization"]="Bearer "+token
 event={"version":"2.0","rawPath":"/mcp","rawQueryString":"","headers":headers,"requestContext":{"stage":"$default","http":{"method":"POST","path":"/mcp"}},"body":body,"isBase64Encoded":False}
 return ep.handler(event,Context())
valid=p["tokens"]["valid"]; out={}
from mapit.aws_dev_runtime import parse_cognito_jwks
from mapit.remote_http import FixedRS256TokenVerifier
import asyncio
policy_for_verify=ep._parse_manifest(manifest_raw)["_validated_policy"]
verifier=FixedRS256TokenVerifier(policy_for_verify,parse_cognito_jwks((root/"mapit"/ep.JWKS_FILENAME).read_bytes()))
out["token_signature_claims_valid"]=asyncio.run(verifier.verify_token(valid)) is not None
def parsed(r):
 try:return json.loads(r.get("body",""))
 except Exception:return {}
init=invoke(valid,rpc("initialize",{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"offline-prod-arm-probe","version":"1"}})); idoc=parsed(init); ir=idoc.get("result",{})
out["initialize"]=init.get("statusCode")==200 and idoc.get("jsonrpc")=="2.0" and "error" not in idoc and ir.get("protocolVersion")=="2025-03-26" and isinstance(ir.get("serverInfo"),dict)
statuses={"initialize":init.get("statusCode",0)}
listing=invoke(valid,rpc("tools/list")); doc=parsed(listing); names=[x.get("name") for x in doc.get("result",{}).get("tools",[])]
expected=["get_vehicle_status","get_vehicle_details","list_routes","get_route_detail","get_distance","compare_distance_periods","get_route_statistics","get_distance_breakdown","get_route_extremes","compare_route_periods"]
geo_enabled=manifest.get("geographic_queries") is True
if geo_enabled: expected.extend(["geographic_summary","summer_geographic_summary"])
out["tools_list_exactly_ten"]=listing.get("statusCode")==200 and len(names)==len(expected) and set(names)==set(expected)
statuses["tools_list"]=listing.get("statusCode",0)
rng={"from_time":"2026-01-01","to_time":"2026-02-01"}; period={"period_a":rng,"period_b":{"from_time":"2026-02-01","to_time":"2026-03-01"}}
calls=[("get_vehicle_status",{}),("get_vehicle_details",{}),("list_routes",rng),("get_route_detail",{"route_id":"synthetic-route"}),("get_distance",rng),("compare_distance_periods",period),("get_route_statistics",rng),("get_distance_breakdown",dict(rng,group_by="day")),("get_route_extremes",rng),("compare_route_periods",period)]
success=0
for i,(name,args) in enumerate(calls,1):
 response=invoke(valid,rpc("tools/call",{"name":name,"arguments":args},i)); result=parsed(response).get("result",{}); success+=response.get("statusCode")==200 and result.get("isError") is False
 if i==1: statuses["first_tool_call"]=response.get("statusCode",0)
out["tool_calls_all_succeeded"]=success==10
a=invoke(valid,rpc("tools/list")); b=invoke(valid,rpc("tools/list")); an=[x.get("name") for x in parsed(a).get("result",{}).get("tools",[])]; bn=[x.get("name") for x in parsed(b).get("result",{}).get("tools",[])]
out["warm_repeat"]=a.get("statusCode")==b.get("statusCode")==200 and len(an)==len(bn)==len(expected) and set(an)==set(bn)==set(expected)
if geo_enabled:
 def geo_call(name,args): return parsed(invoke(valid,rpc("tools/call",{"name":name,"arguments":args}))).get("result",{})
 g=geo_call("geographic_summary",{"area_name":"menorca","from_time":"2026-06-01","to_time":"2026-07-01"}); gd=g.get("structuredContent",{})
 out["geographic_summary_counts_and_km"]=g.get("isError") is False and gd.get("fully_inside_routes")==1 and gd.get("outside_routes")==1 and gd.get("fully_inside_distance_km")==5 and gd.get("unknown_routes")==0
 su=geo_call("summer_geographic_summary",{"area_name":"menorca","year":2026}); sd=su.get("structuredContent",{})
 out["summer_summary_local_boundaries"]=su.get("isError") is False and sd.get("from_time")=="2026-05-31T22:00:00.000Z" and sd.get("to_time")=="2026-08-31T22:00:00.000Z" and sd.get("fully_inside_distance_km")==5
 before=ssm.calls; invalid=geo_call("geographic_summary",{"area_name":"unknown","from_time":"2026-06-01","to_time":"2026-07-01"})
 out["invalid_area_before_ssm"]=invalid.get("isError") is True and ssm.calls==before
 invalid=geo_call("geographic_summary",{"area_name":"alrededores","from_time":"2026-06-01","to_time":"2026-07-01"})
 out["invalid_area_before_ssm"]=out["invalid_area_before_ssm"] and invalid.get("isError") is True and ssm.calls==before
 invalid=geo_call("summer_geographic_summary",{"area_name":"menorca","year":1900})
 out["invalid_year_before_ssm"]=invalid.get("isError") is True and ssm.calls==before
 amb=geo_call("geographic_summary",{"area_name":"Àrea Metropolitana de Barcelona","from_time":"2026-06-01","to_time":"2026-07-01"}); ad=amb.get("structuredContent",{})
 city=geo_call("geographic_summary",{"area_name":"Barcelona","from_time":"2026-06-01","to_time":"2026-07-01"}); cd=city.get("structuredContent",{})
 out["amb_union_and_barcelona_summaries"]=(amb.get("isError") is False and city.get("isError") is False and ad.get("area_source")=="ign_amb_36_municipalities_union_2026_10_03" and cd.get("area_source")=="ign_amb_municipality_34090808019_2026_10_03" and ad.get("fully_inside_routes")==1 and ad.get("outside_routes")==1 and cd.get("fully_inside_routes")==1 and cd.get("outside_routes")==1 and ad.get("fully_inside_distance_km")==5 and cd.get("fully_inside_distance_km")==5)
 from mapit.geography_engine import MENORCA_GEOJSON_SHA256,AMB_GEOJSON_SHA256,AMB_FEATURE_CODES,load_frozen_menorca_area,load_frozen_amb_area,classify_public_area_route
 raw=(root/"mapit"/"data"/"menorca-ign-20261003.geojson").read_bytes()
 amb_raw=(root/"mapit"/"data"/"amb-ign-20261003.geojson").read_bytes()
 out["geometry_asset_digest"]=hashlib.sha256(raw).hexdigest()==MENORCA_GEOJSON_SHA256
 out["amb_asset_digest"]=hashlib.sha256(amb_raw).hexdigest()==AMB_GEOJSON_SHA256
 area=load_frozen_menorca_area(raw); line={"type":"FeatureCollection","features":[{"type":"Feature","geometry":{"type":"LineString","coordinates":[[4.12,39.96],[4.121,39.961]]}}]}
 started=__import__("time").monotonic(); matches=sum(classify_public_area_route(line,area)=="fully_inside" for _ in range(1000)); elapsed=__import__("time").monotonic()-started
 out["geometry_engine_repeat_classification"]=matches==1000 and elapsed<10
 out["geometry_engine_bounded_memory"]=__import__("resource").getrusage(__import__("resource").RUSAGE_SELF).ru_maxrss<230*1024
 from mapit.geographic_tools import _load_selected_area
 out["amb_registry_cache_bounded"]=_load_selected_area.cache_info().maxsize==2 and _load_selected_area.cache_info().currsize<=2 and len(AMB_FEATURE_CODES)==36
missing=invoke(None,rpc("tools/list")).get("statusCode",0); unknown=invoke(p["tokens"]["unknown_kid"],rpc("tools/list")).get("statusCode",0); wrong_aud=invoke(p["tokens"]["wrong_audience"],rpc("tools/list")).get("statusCode",0); wrong_scope=invoke(p["tokens"]["wrong_scope"],rpc("tools/list")).get("statusCode",0)
statuses.update({"missing_auth":missing,"unknown_kid":unknown,"wrong_audience":wrong_aud,"wrong_scope":wrong_scope})
out["missing_auth_401"]=missing==401
out["unknown_kid_401"]=unknown==401
out["wrong_audience_401"]=wrong_aud==401
out["wrong_scope_403"]=wrong_scope==403
def clear(): ep._CACHED_RUNTIME=None; ep._CACHED_MANIFEST_SHA256=None; ep._CACHED_SSM_CLIENT=None
os.environ["MAPIT_MCP_ENV"]="dev"; clear(); dev_status=invoke(valid,rpc("tools/list")).get("statusCode",0); out["dev_isolation_503"]=dev_status==503
os.environ["MAPIT_MCP_ENV"]="prod"; os.environ.pop("MAPIT_PROD_MANIFEST_SHA256",None); clear(); missing_config_status=invoke(valid,rpc("tools/list")).get("statusCode",0); out["missing_config_503"]=missing_config_status==503
statuses.update({"dev_isolation":dev_status,"missing_config":missing_config_status})
out["lazy_ssm_per_invocation"]=ssm.calls==(14 if geo_enabled else 10)
print(json.dumps({"checks":out,"statuses":statuses},sort_keys=True,separators=(",",":"))); sys.exit(0 if all(out.values()) else 2)
'''


class ProbeError(ValueError):
    """Safe closed probe failure."""


def _run_bounded_process(command: list[str], input_text: str, *, timeout: float) -> tuple[int, str]:
    """Run one child with bounded stdout/stderr buffers and a hard CLI timeout."""
    process = None
    overflow = threading.Event()
    writer_failed = threading.Event()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    readers: list[threading.Thread] = []

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
        )
    except Exception:
        raise ProbeError("arm_probe_execution_failed") from None

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
            process.stdin.write(input_text.encode("utf-8", errors="strict"))
            process.stdin.flush()
        except Exception:
            writer_failed.set()
        finally:
            try:
                if process is not None and process.stdin is not None:
                    process.stdin.close()
            except Exception:
                pass

    assert process.stdout is not None and process.stderr is not None
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        thread = threading.Thread(target=read_pipe, args=(name, stream), daemon=True)
        thread.start()
        readers.append(thread)
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
    for thread in readers:
        thread.join(timeout=2)
    if timed_out:
        raise ProbeError("arm_probe_execution_failed")
    if overflow.is_set():
        raise ProbeError("arm_probe_output_invalid")
    if writer.is_alive() or any(thread.is_alive() for thread in readers) or writer_failed.is_set():
        raise ProbeError("arm_probe_execution_failed")
    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
        return_code = process.returncode
    except Exception:
        raise ProbeError("arm_probe_output_invalid") from None
    if type(return_code) is not int:
        raise ProbeError("arm_probe_execution_failed")
    return return_code, stdout


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fixture(policy: CognitoProdPolicy, now: int) -> tuple[bytes, dict[str, str]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks = json.dumps({"keys": [{
        "kty": "RSA", "kid": _KID, "use": "sig", "alg": "RS256",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }]}, sort_keys=True, separators=(",", ":")).encode("ascii")
    def signed(kid: str = _KID, **overrides: Any) -> str:
        header = _b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
        claims = {
            "iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
            "client_id": policy.client_id, "token_use": "access", "iat": now,
            "exp": now + 240, "scope": policy.required_scope,
        }
        claims.update(overrides)
        body = _b64u(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signing = f"{header}.{body}".encode("ascii")
        return f"{header}.{body}.{_b64u(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))}"

    return jwks, {
        "valid": signed(),
        "unknown_kid": signed("unknown-prod-probe-key"),
        "wrong_audience": signed(aud="https://wrong.invalid/mcp"),
        "wrong_scope": signed(scope="https://wrong.invalid/mcp/use"),
    }


def _parse_checks(stdout: str, *, geography_enabled: bool = False) -> tuple[dict[str, bool], dict[str, int]]:
    if type(stdout) is not str or not stdout or len(stdout.encode("utf-8", errors="ignore")) > _MAX_OUTPUT:
        raise ProbeError("arm_probe_output_invalid")
    try:
        value = json.loads(stdout, object_pairs_hook=docker_helpers._reject_duplicate_members,
                           parse_constant=docker_helpers._reject_json_constant)
    except Exception:
        raise ProbeError("arm_probe_output_invalid") from None
    if type(value) is not dict or set(value) != {"checks", "statuses"}:
        raise ProbeError("arm_probe_output_invalid")
    checks, statuses = value["checks"], value["statuses"]
    expected_checks = _CHECKS + (_GEOGRAPHY_CHECKS if geography_enabled else ())
    if type(checks) is not dict or set(checks) != set(expected_checks) or any(type(checks[k]) is not bool for k in expected_checks):
        raise ProbeError("arm_probe_output_invalid")
    expected_statuses = {"initialize", "tools_list", "first_tool_call", "missing_auth", "unknown_kid",
                         "wrong_audience", "wrong_scope", "dev_isolation", "missing_config"}
    if type(statuses) is not dict or set(statuses) != expected_statuses or any(
        type(statuses[k]) is not int or statuses[k] not in {0, 200, 401, 403, 503} for k in expected_statuses
    ):
        raise ProbeError("arm_probe_output_invalid")
    return checks, statuses


def _command(archive: Path, context: str, name: str, run_id: str, cid_file: Path) -> list[str]:
    return ["docker", "--context", context, "run", "--rm", "--pull=never", "-i", "--name", name,
            "--label", f"{docker_helpers._OWNER_LABEL}=honda-mapit-mcp", "--label",
            f"{docker_helpers._RUN_LABEL}={run_id}", "--cidfile", str(cid_file), "--platform", "linux/arm64",
            "--network", "none", "--memory", "256m", "--mount", f"type=bind,source={archive},target=/probe/runtime.zip,readonly",
            "--entrypoint", "python3", IMAGE, "-c", _CONTAINER_PROBE]


def run_probe(wheel_dir: Path, *, geography_wheel_dir: Path | None = None) -> dict[str, Any]:
    """Build and exercise one exact prod ZIP using a synthetic in-container stack."""
    try:
        repo = prod_builder.dev_builder._repo_root()
        wheels = prod_builder.dev_builder._validate_external_wheel_dir(Path(wheel_dir), repo)
        policy = CognitoProdPolicy(
            user_pool_id=_POOL, api_id=_API, client_id=_CLIENT,
            owner_subject=_OWNER, request_deadline_seconds=14.0,
        )
        config = MapitConfig(
            region="eu-west-1", user_pool_id=_POOL, user_pool_client_id=_CLIENT,
            identity_pool_id=_IDENTITY, discovery_enabled=False, http_timeout=2.0,
        )
        now = int(time.time())
        snapshot, tokens = _fixture(policy, now)
        with tempfile.TemporaryDirectory(prefix="honda-mapit-prod-arm-probe-") as temp:
            root = Path(temp).resolve(strict=True)
            prod_builder.dev_builder._outside_repo_and_onedrive(root, repo, "temporary_directory_invalid")
            context = docker_helpers._docker_context()
            jwks_path, archive_path, cid_file = root / "public-jwks.json", root / "runtime.zip", root / "container.cid"
            jwks_path.write_bytes(snapshot)
            summary = prod_builder.build_prod_runtime_archive(
                wheels, jwks_path, archive_path, policy=policy, mapit_config=config,
                account_id=_ACCOUNT, parameter_version=1, parameter_tier="Standard",
                geography_wheel_dir=geography_wheel_dir,
            )
            run_id = uuid.uuid4().hex
            name = f"{_NAME_PREFIX}{run_id}"
            payload = json.dumps({"tokens": tokens}, separators=(",", ":"))
            process_result = None
            process_failure: ProbeError | None = None
            try:
                process_result = _run_bounded_process(
                    _command(archive_path, context, name, run_id, cid_file),
                    payload,
                    timeout=_MAX_DOCKER_SECONDS,
                )
            except ProbeError as exc:
                process_failure = exc
            if not docker_helpers._cleanup_owned_container(context, name, run_id, cid_file):
                raise ProbeError("cleanup_unverified")
            if process_failure is not None:
                raise process_failure
            if process_result is None:
                raise ProbeError("arm_probe_execution_failed")
            return_code, stdout = process_result
            if return_code not in (0, 2):
                raise ProbeError("arm_probe_execution_failed")
            checks, statuses = _parse_checks(stdout, geography_enabled=geography_wheel_dir is not None)
            success = return_code == 0 and all(checks.values())
            return {"success": success, "category": "prod_runtime_arm_probe_passed" if success else "prod_runtime_arm_probe_failed",
                    "zip_bytes": summary.zip_bytes, "zip_sha256": summary.sha256, "wheel_count": summary.wheel_count,
                    "archive_entries": summary.archive_entries, "public_key_count": summary.public_key_count,
                    "checks": checks, "http_statuses": statuses}
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("production_runtime_arm_probe_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--geography-wheel-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.wheel_dir, geography_wheel_dir=args.geography_wheel_dir)
    except Exception as exc:
        category = str(exc) if isinstance(exc, ProbeError) and str(exc) in _SAFE_FAILURES else "production_runtime_arm_probe_failed"
        print(json.dumps({"success": False, "category": category}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
