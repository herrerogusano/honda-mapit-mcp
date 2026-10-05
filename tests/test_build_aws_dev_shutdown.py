from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from scripts import build_aws_dev_shutdown as builder


def _make_stage(root: Path) -> Path:
    root.mkdir()
    dist_to_root = {
        "boto3": "boto3",
        "botocore": "botocore",
        "jmespath": "jmespath",
        "python-dateutil": "dateutil",
        "s3transfer": "s3transfer",
        "six": "six.py",
        "urllib3": "urllib3",
    }
    for distribution, version in builder.PINNED_DISTRIBUTIONS.items():
        root_name = dist_to_root[distribution]
        if root_name == "six.py":
            (root / root_name).write_text("six = True\n", encoding="utf-8")
        else:
            package_root = root / root_name
            package_root.mkdir()
            (package_root / "__init__.py").write_text(f"name = {distribution!r}\n", encoding="utf-8")
            (package_root / "sample.py").write_text("SYNTHETIC = True\n", encoding="utf-8")
        dirname = distribution.replace("-", "_")
        dist_info = root / f"{dirname}-{version}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n",
            encoding="utf-8",
        )
        (dist_info / "RECORD").write_text("", encoding="utf-8")
    return root


@pytest.fixture
def stage(tmp_path):
    return _make_stage(tmp_path / "sdk-stage")


def test_build_is_deterministic_and_contains_only_pinned_sdk_and_minimal_app(tmp_path, stage):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_summary = builder.build_archive(stage, first)
    second_summary = builder.build_archive(stage, second)

    first_bytes = first.read_bytes()
    assert first_bytes == second.read_bytes()
    assert first_summary == second_summary
    assert first_summary.sha256
    assert first_summary.zip_bytes == len(first_bytes)
    assert first_summary.dependencies_valid is True
    assert first_summary.minimal_package_init is True

    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert "mapit/__init__.py" in names
        assert archive.read("mapit/__init__.py") == b""
        assert "mapit/aws_dev_shutdown.py" in names
        assert "mapit/aws_dev_shutdown_entrypoint.py" in names
        assert "mapit/__init__.py" not in {name for name in names if name.startswith("src/")}
        assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)
        assert all(info.date_time == builder.ZIP_TIMESTAMP for info in archive.infolist())
        top_roots = {name.split("/", 1)[0] for name in names}
        expected_dist_info = {
            f"{name.replace('-', '_')}-{version}.dist-info"
            for name, version in builder.PINNED_DISTRIBUTIONS.items()
        }
        assert top_roots == set(builder.PACKAGE_ROOTS) | {"mapit"} | expected_dist_info


def test_pycache_and_bytecode_are_skipped(stage, tmp_path):
    cache = stage / "botocore" / "__pycache__"
    cache.mkdir()
    (cache / "module.cpython-313.pyc").write_bytes(b"compiled")
    (stage / "stray.pyc").write_bytes(b"ignored root cache")
    output = tmp_path / "package.zip"
    builder.build_archive(stage, output)
    with zipfile.ZipFile(output) as archive:
        assert not any("__pycache__" in name or name.endswith(".pyc") for name in archive.namelist())


def _add_expected_jmespath_launcher(stage: Path) -> Path:
    launcher_dir = stage / "bin"
    launcher_dir.mkdir()
    launcher = b"#!/tmp/runtime/python\n" + builder._EXPECTED_JP_LAUNCHER_BODY
    (launcher_dir / "jp.py").write_bytes(launcher)
    dist_info = next(stage.glob("jmespath-*.dist-info"))
    digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(launcher).digest()).rstrip(b"=").decode("ascii")
    (dist_info / "RECORD").write_text(f"../../bin/jp.py,{digest},{len(launcher)}\n", encoding="utf-8")
    return launcher_dir


def test_only_validated_jmespath_pip_launcher_is_accepted_then_omitted(stage, tmp_path):
    _add_expected_jmespath_launcher(stage)
    output = tmp_path / "package.zip"
    builder.build_archive(stage, output)
    with zipfile.ZipFile(output) as archive:
        assert "bin/jp.py" not in archive.namelist()


def test_bin_rejects_extra_content_unexpected_body_and_bad_record(stage, tmp_path):
    launcher_dir = _add_expected_jmespath_launcher(stage)
    (launcher_dir / "unexpected.py").write_text("print('not allowed')\n", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "extra.zip")

    (launcher_dir / "unexpected.py").unlink()
    (launcher_dir / "jp.py").write_bytes(b"#!/tmp/runtime/python\nprint('not allowed')\n")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "body.zip")

    expected = b"#!/tmp/runtime/python\n" + builder._EXPECTED_JP_LAUNCHER_BODY
    (launcher_dir / "jp.py").write_bytes(expected)
    dist_info = next(stage.glob("jmespath-*.dist-info"))
    (dist_info / "RECORD").write_text(f"../../bin/jp.py,sha256=invalid,{len(expected)}\n", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "record.zip")


def test_unexpected_roots_and_unexpected_distribution_are_rejected_before_output(stage, tmp_path):
    (stage / "rogue-root.txt").write_text("not an allowed dependency", encoding="utf-8")
    output = tmp_path / "package.zip"
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, output)
    assert not output.exists()


def test_exact_distribution_pins_are_checked_from_metadata(stage, tmp_path):
    metadata = next(stage.glob("boto3-*.dist-info/METADATA"))
    metadata.write_text(
        f"Metadata-Version: 2.1\nName: boto3\nVersion: 0.0.1\n\n",
        encoding="utf-8",
    )
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_wrong_dist_info_directory_identity_is_rejected(stage, tmp_path):
    info = next(stage.glob("jmespath-*.dist-info"))
    renamed = stage / "jmespath-wrong.dist-info"
    info.rename(renamed)
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_pth_files_are_rejected_even_inside_an_allowed_package(stage, tmp_path):
    (stage / "boto3" / "unsafe.pth").write_text("import os", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_obvious_secret_file_names_are_rejected_inside_package_roots(stage, tmp_path):
    (stage / "botocore" / ".env.local").write_text("SHOULD_NOT_SHIP=x", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_symlink_is_rejected_without_following_it(stage, tmp_path):
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    link = stage / "botocore" / "linked.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable in this environment")
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_output_must_be_outside_repository_and_dependency_stage(stage, tmp_path):
    repo_output = builder._repository_root() / "not-created-shutdown.zip"
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, repo_output)
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, stage / "inside-stage.zip")
    assert not repo_output.exists()
    assert not (stage / "inside-stage.zip").exists()


@pytest.mark.parametrize("limit_name", ["MAX_FILE_BYTES", "MAX_TOTAL_BYTES"])
def test_file_and_total_size_limits_fail_closed(stage, tmp_path, monkeypatch, limit_name):
    monkeypatch.setattr(builder, limit_name, 1)
    with pytest.raises(builder.BuildError):
        builder.build_archive(stage, tmp_path / "package.zip")


def test_cli_requires_dependency_dir_and_output():
    with pytest.raises(SystemExit):
        builder.main([])


def test_cli_reports_only_safe_archive_metadata(stage, tmp_path, capsys):
    output = tmp_path / "external.zip"
    result = builder.main(["--dependency-dir", str(stage), "--output", str(output)])
    printed = capsys.readouterr()
    payload = json.loads(printed.out)
    assert result == 0
    assert set(payload) == {
        "success", "category", "zip_bytes", "sha256", "dependencies_valid", "minimal_package_init"
    }
    assert payload["success"] is True
    assert payload["dependencies_valid"] is True
    assert payload["minimal_package_init"] is True
    assert str(stage) not in printed.out
    assert str(output) not in printed.out
    assert printed.err == ""


def test_cli_failure_does_not_emit_source_paths_or_errors(stage, tmp_path, capsys):
    (stage / "unexpected-secret-canary.txt").write_text("x", encoding="utf-8")
    result = builder.main(["--dependency-dir", str(stage), "--output", str(tmp_path / "external.zip")])
    printed = capsys.readouterr()
    payload = json.loads(printed.out)
    assert result == 1
    assert payload == {"success": False, "category": "shutdown_package_build_failed"}
    assert str(stage) not in printed.out
    assert "unexpected-secret-canary" not in printed.out
    assert printed.err == ""
