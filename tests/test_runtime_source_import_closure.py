"""Import only each selected runtime's bundled sources, never the repo package."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import build_aws_dev_runtime as dev
from scripts import build_aws_dev_multiuser_archive as multi
from scripts import build_aws_dev_enrolled_archive as enrolled
from scripts import build_aws_prod_runtime as prod

SOURCE = Path(__file__).resolve().parents[1] / "src" / "mapit"
PROFILES = [
    (dev.SOURCE_MODULES, "aws_dev_entrypoint"),
    (multi.SOURCE_MODULES, "aws_dev_multiuser_entrypoint"),
    (enrolled.SOURCE_MODULES, "aws_dev_enrolled_entrypoint"),
    (prod.PROD_SOURCE_MODULES, "aws_prod_entrypoint"),
    (prod.PROD_SOURCE_MODULES + prod.GEOGRAPHY_SOURCE_MODULES, "aws_prod_entrypoint"),
]


@pytest.mark.parametrize("modules,entrypoint", PROFILES)
def test_unconditional_relative_imports_are_bundled(modules, entrypoint):
    bundled = {Path(name).stem for name in modules}
    assert len(bundled) == len(modules)
    for name in modules:
        tree = ast.parse((SOURCE / name).read_bytes())
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.level == 1 and statement.module:
                assert statement.module.split(".")[0] in bundled, (entrypoint, name, statement.module)


@pytest.mark.parametrize("modules,entrypoint", PROFILES)
def test_isolated_entrypoint_import_has_no_repository_fallback(tmp_path, modules, entrypoint):
    package = tmp_path / "mapit"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"")
    for name in modules:
        (package / name).write_bytes((SOURCE / name).read_bytes())
    code = r'''
import importlib, pathlib, socket, sys
def denied(*args, **kwargs):
    raise AssertionError("runtime_import_network_denied")
socket.create_connection = socket.getaddrinfo = denied
socket.socket.connect = socket.socket.connect_ex = denied
socket.socket.sendto = socket.socket.sendall = denied
# Editable install finders can ignore the selected package's __path__.
sys.meta_path[:] = [finder for finder in sys.meta_path
    if not getattr(finder, "__module__", "").startswith("__editable__")]
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
loaded = importlib.import_module("mapit." + sys.argv[2])
for name, module in tuple(sys.modules.items()):
    if name == "mapit" or name.startswith("mapit."):
        location = pathlib.Path(module.__file__).resolve()
        assert location.is_relative_to(root), "repository_fallback_rejected"
print("import_verified")
'''
    environment = {name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH")
                   if name in os.environ}
    result = subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path), entrypoint],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "import_verified"


@pytest.mark.parametrize("modules,entrypoint", [PROFILES[1], PROFILES[3]])
def test_omitted_identity_module_fails_in_isolated_package(tmp_path, modules, entrypoint):
    incomplete = tuple(name for name in modules if name != "mapit_identity.py")
    with pytest.raises(AssertionError, match=r"mapit\.mapit_identity"):
        test_isolated_entrypoint_import_has_no_repository_fallback(tmp_path, incomplete, entrypoint)
