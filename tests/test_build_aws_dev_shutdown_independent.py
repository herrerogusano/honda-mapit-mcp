from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from scripts import build_aws_dev_shutdown as builder


def _synthetic_stage(root: Path) -> Path:
    root.mkdir()
    package_roots = {
        "boto3": "boto3",
        "botocore": "botocore",
        "jmespath": "jmespath",
        "python-dateutil": "dateutil",
        "s3transfer": "s3transfer",
        "six": "six.py",
        "urllib3": "urllib3",
    }
    for distribution, version in builder.PINNED_DISTRIBUTIONS.items():
        root_name = package_roots[distribution]
        if root_name == "six.py":
            (root / root_name).write_text("SIX_TEST_FIXTURE = True\n", encoding="utf-8")
        else:
            package = root / root_name
            package.mkdir()
            (package / "__init__.py").write_text("SYNTHETIC_PACKAGE = True\n", encoding="utf-8")
        info = root / f"{distribution.replace('-', '_')}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n",
            encoding="utf-8",
        )
        (info / "RECORD").write_text("", encoding="utf-8")
    return root


def _write_launcher(stage: Path, body: bytes | None = None) -> tuple[Path, Path]:
    bin_dir = stage / "bin"
    bin_dir.mkdir()
    payload = b"#!/tmp/runtime/python\n" + (builder._EXPECTED_JP_LAUNCHER_BODY if body is None else body)
    launcher = bin_dir / "jp.py"
    launcher.write_bytes(payload)
    record = next(stage.glob("jmespath-*.dist-info")) / "RECORD"
    digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
    record.write_text(f"../../bin/jp.py,{digest},{len(payload)}\n", encoding="utf-8")
    return launcher, record


def test_exact_record_bound_pip_launcher_is_accepted_but_never_packaged(tmp_path):
    stage = _synthetic_stage(tmp_path / "stage")
    _write_launcher(stage)
    output = tmp_path / "shutdown.zip"
    builder.build_archive(stage, output)
    import zipfile

    with zipfile.ZipFile(output) as archive:
        assert "bin/jp.py" not in archive.namelist()


def test_launcher_with_extra_script_is_rejected_and_never_packaged(tmp_path):
    stage = _synthetic_stage(tmp_path / "stage")
    bin_dir = stage / "bin"
    bin_dir.mkdir()
    (bin_dir / "rogue.py").write_text("print('launcher-canary')\n", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "shutdown.zip")
    assert not (tmp_path / "shutdown.zip").exists()


def test_jmespath_launcher_body_is_checked_even_when_record_matches_it(tmp_path):
    stage = _synthetic_stage(tmp_path / "stage")
    _write_launcher(stage, b"import os\nos.system('do-not-run')\n")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "shutdown.zip")
    assert not (tmp_path / "shutdown.zip").exists()


@pytest.mark.parametrize("bad_record", [
    "../../bin/jp.py,sha256=wrong,99\n",
    "../../bin/jp.py,sha256=wrong,",
    "../../bin/jp.py,sha256=wrong,1\n../../bin/jp.py,sha256=wrong,1\n",
])
def test_launcher_record_hash_size_and_uniqueness_are_required(tmp_path, bad_record):
    stage = _synthetic_stage(tmp_path / "stage")
    _launcher, record = _write_launcher(stage)
    record.write_text(bad_record, encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "shutdown.zip")
    assert not (tmp_path / "shutdown.zip").exists()


def test_oversized_record_is_rejected_before_reading_whole_file(tmp_path, monkeypatch):
    stage = _synthetic_stage(tmp_path / "stage")
    _launcher, record = _write_launcher(stage)
    record.write_bytes(b"x" * (builder.MAX_METADATA_BYTES + 1))
    real_open = Path.open
    record_reads = []

    class ReadSpy:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            record_reads.append(size)
            return self.stream.read(size)

    def checked_open(path, *args, **kwargs):
        if path == record:
            return ReadSpy(real_open(path, *args, **kwargs))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked_open)
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "shutdown.zip")
    assert record_reads == []
    assert not (tmp_path / "shutdown.zip").exists()
