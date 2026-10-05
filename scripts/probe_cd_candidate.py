"""Exact private release ZIP acceptance in the pinned offline ARM container."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from pathlib import Path

from scripts import probe_aws_dev_runtime_arm as docker_helpers
from scripts.probe_aws_prod_runtime_arm import IMAGE, _run_bounded_process

CHECKS = frozenset({"archive_digest", "manifest_digest", "source_binding", "native_imports",
                   "missing_auth", "warm_repeat", "invalid_config", "lazy_ssm", "geometry_load"})

PROBE = r'''
import hashlib,json,os,pathlib,socket,sys,tempfile,zipfile
checks={key:False for key in ("archive_digest","manifest_digest","source_binding","native_imports","missing_auth","warm_repeat","invalid_config","lazy_ssm","geometry_load")}
try:
    expected=json.loads(sys.stdin.read(1024))
    raw=pathlib.Path("/probe/runtime.zip").read_bytes()
    assert len(raw)<=50*1024*1024 and hashlib.sha256(raw).hexdigest()==expected["zip_sha256"]
    checks["archive_digest"]=True
    root=pathlib.Path(tempfile.mkdtemp(prefix="cd-probe-"))
    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
        assert len(archive.infolist())<30000 and sum(i.file_size for i in archive.infolist())<=100*1024*1024
        for info in archive.infolist():
            p=pathlib.PurePosixPath(info.filename)
            assert not p.is_absolute() and ".." not in p.parts and "\\" not in info.filename
        manifest=archive.read("mapit/mapit-prod.manifest.json")
        jwks=archive.read("mapit/cognito-public-jwks.json")
        assert hashlib.sha256(manifest).hexdigest()==expected["manifest_sha256"]
        checks["manifest_digest"]=True
        if expected["source_sha"] is not None:
            assert json.loads(archive.read("mapit/source-provenance.json"))=={"schema":1,"source_sha":expected["source_sha"]}
        checks["source_binding"]=True
        archive.extractall(root)
    import ssl
    def deny_network(*args,**kwargs):raise RuntimeError("network_denied")
    native_socket=socket.socket
    class GuardSocket(native_socket):
        def connect(self,address):
            if self.family in (socket.AF_INET,socket.AF_INET6):deny_network()
            return super().connect(address)
        def connect_ex(self,address):
            if self.family in (socket.AF_INET,socket.AF_INET6):deny_network()
            return super().connect_ex(address)
    socket.socket=GuardSocket
    socket.create_connection=deny_network
    sys.path.insert(0,str(root))
    import mapit.aws_prod_entrypoint as ep
    import cryptography.hazmat.bindings._rust
    import shapely
    checks["native_imports"]=True
    attempts=[]
    def deny_ssm():
        attempts.append(True)
        raise RuntimeError("ssm_denied")
    ep._ssm_client_factory=deny_ssm
    digest=expected["manifest_sha256"]
    os.environ.update({"AWS_LAMBDA_FUNCTION_NAME":"honda-mapit-mcp-prod-handler","AWS_REGION":"eu-west-1","MAPIT_MCP_ENV":"prod","MAPIT_PROD_MANIFEST_SHA256":digest})
    config=json.loads(manifest)
    event={"version":"2.0","rawPath":"/mcp","requestContext":{"http":{"method":"POST","path":"/mcp"}},"headers":{"host":config["api_id"]+".execute-api.eu-west-1.amazonaws.com","content-type":"application/json"},"body":json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),"isBase64Encoded":False}
    class Context:
        def get_remaining_time_in_millis(self):return 14000
    first=ep.handler(event,Context())
    assert first["statusCode"]==401
    checks["missing_auth"]=True
    cached=ep._CACHED_RUNTIME
    assert cached is not None and ep.handler(event,Context())["statusCode"]==401 and ep._CACHED_RUNTIME is cached
    checks["warm_repeat"]=True
    os.environ["MAPIT_PROD_MANIFEST_SHA256"]="0"*64
    assert ep.handler(event,Context())["statusCode"]==503
    checks["invalid_config"]=True
    assert not attempts and ep._CACHED_SSM_CLIENT is None
    checks["lazy_ssm"]=True
    from mapit.geography_engine import load_frozen_menorca_area
    assert load_frozen_menorca_area((root/"mapit/data/menorca-ign-20261003.geojson").read_bytes()) is not None
    checks["geometry_load"]=True
except BaseException:
    pass
print(json.dumps({"checks":checks},sort_keys=True,separators=(",",":")))
'''


def probe_candidate(archive: Path, *, zip_sha256: str, manifest_sha256: str,
                    source_sha: str | None, report=None) -> bool:
    """Never emits container logs or real bindings; returns a closed boolean."""
    try:
        if any(type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None for v in (zip_sha256, manifest_sha256)):
            return False
        if source_sha is not None and (type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None):
            return False
        if not archive.is_file() or archive.stat().st_size > 50 * 1024 * 1024 or hashlib.sha256(archive.read_bytes()).hexdigest() != zip_sha256:
            return False
        context = docker_helpers._docker_context()
        run_id = uuid.uuid4().hex
        name = "honda-mapit-cd-probe-" + run_id
        with tempfile.TemporaryDirectory(prefix="cd-arm-receipt-") as scratch:
            cid = Path(scratch) / "container.cid"
            command = ["docker", "--context", context, "run", "--rm", "--pull=never", "-i", "--name", name,
                       "--label", f"{docker_helpers._OWNER_LABEL}=honda-mapit-mcp",
                       "--label", f"{docker_helpers._RUN_LABEL}={run_id}", "--cidfile", str(cid),
                       "--platform", "linux/arm64", "--network", "none", "--memory", "256m",
                       "--mount", f"type=bind,source={archive.resolve()},target=/probe/runtime.zip,readonly",
                       "--entrypoint", "python3", IMAGE, "-c", PROBE]
            try:
                status, stdout = _run_bounded_process(command, json.dumps({
                    "zip_sha256": zip_sha256, "manifest_sha256": manifest_sha256, "source_sha": source_sha,
                }), timeout=240)
            finally:
                cleaned = docker_helpers._cleanup_owned_container(context, name, run_id, cid)
            value = json.loads(stdout)
            if (type(value) is dict and set(value) == {"checks"} and type(value["checks"]) is dict and
                    set(value["checks"]) == CHECKS and all(type(v) is bool for v in value["checks"].values()) and callable(report)):
                report({key: value["checks"][key] for key in sorted(CHECKS)})
            return (cleaned and status == 0 and type(value) is dict and set(value) == {"checks"} and
                    type(value["checks"]) is dict and set(value["checks"]) == CHECKS and
                    all(v is True for v in value["checks"].values()))
    except Exception:
        return False
