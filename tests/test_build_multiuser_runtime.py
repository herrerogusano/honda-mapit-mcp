from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from scripts import build_aws_dev_runtime as dev_builder
from scripts import build_multiuser_runtime as builder

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "src" / "mapit"
HAVE_SOURCES = all((SOURCE / name).is_file() for name in builder.ROOT_MODULES)


def _write(root: Path, name: str, text: str) -> None:
    (root / name).write_text(text, encoding="utf-8")


def test_inventory_follows_relative_absolute_and_lazy_imports(tmp_path):
    root = tmp_path / "mapit"
    root.mkdir()
    _write(root, "a.py", "from .b import x\nimport mapit.c\n")
    _write(root, "b.py", "def f():\n    from . import d\n")
    _write(root, "c.py", "from mapit import e\n")
    _write(root, "d.py", "")
    _write(root, "e.py", "import json\n")
    _write(root, "unused.py", "")
    assert builder.source_module_inventory(root, ("a.py",)) == ("a.py", "b.py", "c.py", "d.py", "e.py")


def test_inventory_rejects_missing_module(tmp_path):
    root = tmp_path / "mapit"
    root.mkdir()
    _write(root, "a.py", "from .missing import x\n")
    with pytest.raises(builder.MultiuserBuildError, match="runtime_source_missing"):
        builder.source_module_inventory(root, ("a.py",))
    with pytest.raises(builder.MultiuserBuildError, match="runtime_source_invalid"):
        builder.source_module_inventory(root, ("absent.py",))


def test_deterministic_zip_is_stable_and_rejects_collisions():
    entries = [("b.txt", b"2"), ("a.txt", b"1")]
    first = builder.deterministic_zip(entries)
    assert first == builder.deterministic_zip(list(reversed(entries)))
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == ["a.txt", "b.txt"]
        assert all(info.date_time == dev_builder.ZIP_TIMESTAMP for info in archive.infolist())
    with pytest.raises(builder.MultiuserBuildError, match="collision"):
        builder.deterministic_zip([("A.txt", b""), ("a.txt", b"")])


@pytest.mark.skipif(not HAVE_SOURCES, reason="multiuser source modules not present yet")
def test_full_build_with_locked_wheel_seam(tmp_path, monkeypatch):
    # Wheel hash/unpack validation has its own suite; this checks source selection and output.
    monkeypatch.setattr(dev_builder, "_read_lock", lambda _repo: {"fixture": ("1.0", "0" * 64)})
    monkeypatch.setattr(dev_builder, "_wheel_file_inventory", lambda _root, _lock: [("fixture-1.0-py3-none-any.whl", b"w")])
    monkeypatch.setattr(dev_builder, "_unpack_wheels", lambda _w, _l: [("fixture_pkg/__init__.py", b"")])
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    output = tmp_path / "out.zip"
    summary = builder.build_multiuser_archive(wheels, output)
    data = output.read_bytes()
    assert summary.sha256 == hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = set(archive.namelist())
    assert "fixture_pkg/__init__.py" in names and "mapit/__init__.py" in names
    assert {f"mapit/{name}" for name in builder.ROOT_MODULES} <= names
    assert not any(name.endswith(".geojson") for name in names)
    with pytest.raises(builder.MultiuserBuildError, match="output_path_invalid"):
        builder.build_multiuser_archive(wheels, output)  # never overwrites
    with pytest.raises(builder.MultiuserBuildError, match="output_path_invalid"):
        builder.build_multiuser_archive(wheels, REPO / "should-not-exist.zip")


_IMPORT_CODE = r'''
import importlib, pathlib, socket, sys
def denied(*args, **kwargs):
    raise AssertionError("runtime_import_network_denied")
socket.create_connection = socket.getaddrinfo = denied
socket.socket.connect = socket.socket.connect_ex = denied
sys.meta_path[:] = [finder for finder in sys.meta_path
    if not getattr(finder, "__module__", "").startswith("__editable__")]
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
for name in sys.argv[2:]:
    module = importlib.import_module("mapit." + name)
    assert callable(module.handler), name
for name, module in tuple(sys.modules.items()):
    if name == "mapit" or name.startswith("mapit."):
        assert pathlib.Path(module.__file__).resolve().is_relative_to(root), "repository_fallback_rejected"
print("import_verified")
'''


@pytest.mark.skipif(not HAVE_SOURCES, reason="multiuser source modules not present yet")
def test_handlers_import_from_extracted_archive_in_isolated_interpreter(tmp_path):
    """Third-party packages come from the test interpreter; mapit only from the ZIP."""
    entries, _modules = builder.source_entries(REPO)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(io.BytesIO(builder.deterministic_zip(entries))) as archive:
        archive.extractall(extracted)
    environment = {name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH")
                   if name in os.environ}
    environment["AWS_LAMBDA_FUNCTION_NAME"] = "honda-mapit-mcp-dev-mcp"
    result = subprocess.run([sys.executable, "-I", "-c", _IMPORT_CODE, str(extracted), *builder.HANDLER_MODULES],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr[-3000:]
    assert result.stdout.strip() == "import_verified"
