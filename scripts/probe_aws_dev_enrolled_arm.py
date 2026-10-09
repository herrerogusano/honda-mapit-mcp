"""Network-denied ARM readiness, not MAPIT business acceptance.

Packages the enrolled handler with synthetic public inputs. The actual handler
parses those packaged inputs and authenticates a synthetic signed request.
Only an in-memory authorization reader is supplied; session loading deliberately
fails. No enrollment, key material, MAPIT session or external request is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import uuid

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import build_aws_dev_enrolled_archive as builder
from scripts import build_aws_dev_runtime as base
from scripts import probe_aws_dev_multiuser_arm as multi

CHECKS = ("archive_import", "manifest_valid", "independent_jwks",
          "runtime_imported", "tools_list_exactly_ten", "anonymous_denied",
          "missing_session_denied", "revocation_denied", "expired_window_denied")


def _fixture():
    legacy_raw, invitation, tokens, _ = multi._fixture()
    _, mapit, _, _ = multi._fixture()
    legacy = json.loads(legacy_raw)
    value = {
        "schema": 1, "builder": "build_dev_enrolled_archive", "environment": "dev",
        "mode": "mapit-enrolled", "source_sha": multi.SOURCE_SHA,
        "api_id": multi.API_ID, "user_pool_id": multi.POOL_ID, "client_id": multi.CLIENT_ID,
        "invitation_jwks_sha256": hashlib.sha256(invitation).hexdigest(),
        "mapit_jwks_sha256": hashlib.sha256(mapit).hexdigest(),
        "authorization_table_arn": f"arn:aws:dynamodb:eu-west-1:{multi.ACCOUNT_ID}:table/honda-mapit-mcp-dev-tenants",
        "binding_table_arn": f"arn:aws:dynamodb:eu-west-1:{multi.ACCOUNT_ID}:table/honda-mapit-mcp-dev-mapit-identity-bindings",
        "key_parameter_path": "/honda-mapit-mcp/dev/mapit-identity-binding-config",
        "key_publication_start_epoch": multi.START, "key_publication_end_epoch": multi.END,
        "mapit_config": {"region": "eu-west-1", "user_pool_id": "eu-west-1_MapitPool123",
            "user_pool_client_id": "MapitClient123",
            "identity_pool_id": "eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
            "frontend_url": "https://app.mapit.me/", "discovery_enabled": False, "http_timeout": 2.0},
        "tenants": [{"key": row["key"], "subject": row["subject"]} for row in legacy["tenants"]],
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    payload = {"manifest": value, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
               "account_id": multi.ACCOUNT_ID, "start": multi.START, "end": multi.END,
               "now": multi.START + 60, "token": tokens["a"], "key": multi.TENANT_KEYS[0]}
    return raw, invitation, mapit, payload


_CONTAINER_PROBE = r'''import hashlib,io,json,os,sys,tempfile,zipfile
from pathlib import Path
p=json.loads(sys.stdin.read(65536)); out={key:False for key in p["checks"]}
try:
 root=Path(tempfile.mkdtemp(prefix="dev-enrolled-arm-"))
 raw=Path("/probe/runtime.zip").read_bytes()
 with zipfile.ZipFile(io.BytesIO(raw)) as z: z.extractall(root)
 out["archive_import"]=True
 sys.path.insert(0,str(root))
 import mapit.aws_dev_enrolled_entrypoint as ep
 from mapit.aws_enrollment_clients import EnrollmentAwsClients
 out["runtime_imported"]=True
 m=p["manifest"]
 manifest=ep._read(ep.MANIFEST_FILENAME,ep.MAX_MANIFEST_BYTES)
 invitation=ep._read(ep.INVITATION_JWKS_FILENAME,ep.MAX_JWKS_BYTES)
 mapit=ep._read(ep.MAPIT_JWKS_FILENAME,ep.MAX_JWKS_BYTES)
 parsed=ep.parse_enrolled_dev_manifest(manifest,invitation,mapit,expected_digest=p["manifest_sha256"],account_id=p["account_id"])
 out["manifest_valid"]=hashlib.sha256(manifest).hexdigest()==p["manifest_sha256"]
 out["independent_jwks"]=invitation!=mapit and len(parsed.invitation_keys)==1 and len(parsed.mapit_keys)==1
 os.environ.update({"MAPIT_MCP_ENV":"dev","AWS_REGION":"eu-west-1","MAPIT_DEV_ENROLLED_MODE":"mapit-enrolled",
  "MAPIT_DEV_ENROLLED_MANIFEST_SHA256":p["manifest_sha256"],"MAPIT_DEV_EXPECTED_ACCOUNT_ID":p["account_id"],
  "MAPIT_DEV_EXECUTION_START_EPOCH":str(p["start"]),"MAPIT_DEV_EXECUTION_END_EPOCH":str(p["end"]),
  "MAPIT_SOURCE_SHA256":m["source_sha"],"MAPIT_COGNITO_JWKS_SHA256":m["invitation_jwks_sha256"],
  "MAPIT_IDENTITY_JWKS_SHA256":m["mapit_jwks_sha256"],"MAPIT_OBSERVED_API_ID":m["api_id"],
  "MAPIT_COGNITO_USER_POOL_ID":m["user_pool_id"],"MAPIT_COGNITO_CLIENT_ID":m["client_id"]})
 ep.time.time=lambda:float(p["now"])
 class Reader:
  status="active"
  def get_item(self,**request):
   assert request["TableName"]==m["authorization_table_arn"] and request["ConsistentRead"] is True
   assert request["Key"]=={"key":{"S":p["key"]}}
   return {"ResponseMetadata":{"HTTPStatusCode":200},"Item":{"key":{"S":p["key"]},"status":{"S":self.status},"revision":{"N":"1"}}}
 reader=Reader()
 ep._clients=lambda deadline:EnrollmentAwsClients(None,lambda *args:False,reader,lambda client,account:client is reader and account==p["account_id"])
 loads=[]
 def missing_resources(manifest,account):
  def load(**kwargs):
   loads.append(True)
   raise ValueError("synthetic_session_absent")
  return load
 ep._resources_loader=missing_resources
 class C:
  def get_remaining_time_in_millis(self):return 30000
 def call(method,params=None,token=None):
  body=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or {}},separators=(",",":"))
  headers={"host":m["api_id"]+".execute-api.eu-west-1.amazonaws.com","content-type":"application/json","content-length":str(len(body.encode())),"accept":"application/json, text/event-stream"}
  if token:headers["authorization"]="Bearer "+token
  return ep.handler({"version":"2.0","rawPath":"/mcp","rawQueryString":"","headers":headers,"requestContext":{"stage":"$default","http":{"method":"POST","path":"/mcp"}},"body":body,"isBase64Encoded":False},C())
 def body(response):
  try:return json.loads(response.get("body",""))
  except Exception:return {}
 listed=body(call("tools/list",token=p["token"])); names=[x.get("name") for x in listed.get("result",{}).get("tools",[])]
 expected={"get_vehicle_status","get_vehicle_details","list_routes","get_route_detail","get_distance","compare_distance_periods","get_route_statistics","get_distance_breakdown","get_route_extremes","compare_route_periods"}
 out["tools_list_exactly_ten"]=len(names)==10 and set(names)==expected and not loads
 anonymous=call("tools/list"); out["anonymous_denied"]=anonymous.get("statusCode") in (401,403) and not loads
 result=body(call("tools/call",{"name":"get_vehicle_status","arguments":{}},p["token"]))
 out["missing_session_denied"]=result.get("result",{}).get("isError") is True and len(loads)==1
 reader.status="revoked"
 revoked=body(call("tools/call",{"name":"get_vehicle_status","arguments":{}},p["token"]))
 out["revocation_denied"]=revoked.get("result",{}).get("isError") is True and len(loads)==1
 p["now"]=p["end"]
 out["expired_window_denied"]=call("tools/list",token=p["token"]).get("statusCode")==503 and len(loads)==1
except BaseException:pass
print(json.dumps({"checks":out},sort_keys=True,separators=(",",":")));sys.exit(0 if all(out.values()) else 2)
'''


def _parse_output(stdout):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    try:
        value = json.loads(stdout, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {"checks"}
                or type(value["checks"]) is not dict or set(value["checks"]) != set(CHECKS)
                or any(type(flag) is not bool for flag in value["checks"].values())):
            raise ValueError
        return value["checks"]
    except Exception:
        raise multi.ProbeError("arm_probe_output_invalid") from None


def _docker_command(archive, *, context, name, cidfile, run_id):
    command = multi._docker_command(archive, context=context, name=name, cidfile=cidfile, run_id=run_id)
    command[-1] = _CONTAINER_PROBE
    return command


def probe_candidate_archive(archive, *, context, payload):
    if not isinstance(archive, Path) or not archive.is_file():
        raise multi.ProbeError("temporary_directory_invalid")
    run_id = uuid.uuid4().hex
    name = f"honda-mapit-dev-enrolled-arm-{run_id[:12]}"
    with tempfile.TemporaryDirectory(prefix="honda-mapit-dev-enrolled-arm-") as scratch:
        cidfile = Path(scratch) / "cid"
        command = _docker_command(archive, context=context, name=name, cidfile=cidfile, run_id=run_id)
        try:
            status, stdout = multi._run_bounded(command, json.dumps(payload, separators=(",", ":")))
            checks = _parse_output(stdout)
        finally:
            try:
                cleaned = multi.docker_helpers._cleanup_owned_container(context, name, run_id, cidfile)
            except Exception:
                cleaned = False
        if not cleaned:
            raise multi.ProbeError("cleanup_unverified")
    ok = status == 0 and all(checks.values())
    return {"success": ok, "category": "enrolled_arm_readiness_passed" if ok else "enrolled_arm_readiness_failed", "checks": checks}


def run_probe(wheel_dir, *, docker_context=None):
    repo = base._repo_root()
    wheels = base._validate_external_wheel_dir(Path(wheel_dir), repo)
    raw, invitation, mapit, payload = _fixture()
    with tempfile.TemporaryDirectory(prefix="honda-mapit-dev-enrolled-arm-") as scratch:
        root = Path(scratch).resolve(strict=True)
        base._outside_repo_and_onedrive(root, repo, "temporary_directory_invalid")
        paths = (root / "manifest.json", root / "invitation.json", root / "mapit.json")
        for path, value in zip(paths, (raw, invitation, mapit)):
            path.write_bytes(value)
        archive = root / "runtime.zip"
        summary = builder.build_dev_enrolled_archive(wheels, *paths, archive, account_id=multi.ACCOUNT_ID)
        context = multi.docker_helpers._docker_context()
        if docker_context is not None and docker_context != context:
            raise multi.ProbeError("local_docker_context_unavailable")
        result = probe_candidate_archive(archive, context=context, payload={**payload, "checks": list(CHECKS)})
        result["wheel_count"] = summary.wheel_count
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.wheel_dir)
    except Exception as exc:
        category = str(exc) if str(exc) in multi.SAFE_FAILURES else "enrolled_arm_readiness_failed"
        print(json.dumps({"success": False, "category": category}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
