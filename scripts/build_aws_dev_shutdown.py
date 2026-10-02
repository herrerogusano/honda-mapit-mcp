"""Build a deterministic, dependency-isolated dev shutdown Lambda ZIP."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_FILE_COUNT = 20_000
MAX_ROOT_ENTRIES = 64
MAX_METADATA_BYTES = 1024 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

PINNED_DISTRIBUTIONS = {
    "boto3": "1.43.107",
    "botocore": "1.43.107",
    "jmespath": "1.1.0",
    "python-dateutil": "2.9.0.post0",
    "s3transfer": "0.19.2",
    "six": "1.17.0",
    "urllib3": "2.8.0",
}
PACKAGE_ROOTS = frozenset({"boto3", "botocore", "jmespath", "dateutil", "s3transfer", "urllib3", "six.py"})
APP_MODULES = (
    ("mapit/__init__.py", b""),
    ("mapit/aws_dev_shutdown.py", None),
    ("mapit/aws_dev_shutdown_entrypoint.py", None),
)
_NAME_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_DENIED_BASENAMES = frozenset({"credentials", "credentials.json", "aws_credentials", "id_rsa", "id_ed25519"})
_EXPECTED_JP_LAUNCHER_BODY = b"""
import sys
import json
import argparse
from pprint import pformat

import jmespath
from jmespath import exceptions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('expression')
    parser.add_argument('-f', '--filename',
                        help=('The filename containing the input data.  '
                              'If a filename is not given then data is '
                              'read from stdin.'))
    parser.add_argument('--ast', action='store_true',
                        help=('Pretty print the AST, do not search the data.'))
    args = parser.parse_args()
    expression = args.expression
    if args.ast:
        # Only print the AST
        expression = jmespath.compile(args.expression)
        sys.stdout.write(pformat(expression.parsed))
        sys.stdout.write('\\n')
        return 0
    if args.filename:
        with open(args.filename, 'r') as f:
            data = json.load(f)
    else:
        data = sys.stdin.read()
        data = json.loads(data)
    try:
        sys.stdout.write(json.dumps(
            jmespath.search(expression, data), indent=4, ensure_ascii=False))
        sys.stdout.write('\\n')
    except exceptions.ArityError as e:
        sys.stderr.write("invalid-arity: %s\\n" % e)
        return 1
    except exceptions.JMESPathTypeError as e:
        sys.stderr.write("invalid-type: %s\\n" % e)
        return 1
    except exceptions.UnknownFunctionError as e:
        sys.stderr.write("unknown-function: %s\\n" % e)
        return 1
    except exceptions.ParseError as e:
        sys.stderr.write("syntax-error: %s\\n" % e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
"""


class BuildError(ValueError):
    """A fixed-category input or validation failure for the build process."""


@dataclass(frozen=True)
class BuildSummary:
    zip_bytes: int
    sha256: str
    dependencies_valid: bool
    minimal_package_init: bool


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        raise BuildError("build_input_invalid") from None
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & reparse_flag)


def _read_bounded_file(path: Path, byte_limit: int, *, invalid_category: str, oversized_category: str) -> bytes:
    """Check size before opening, then cap the actual read to limit+1 bytes."""
    try:
        size = path.stat().st_size
        if size > byte_limit:
            raise BuildError(oversized_category)
        with path.open("rb") as stream:
            raw = stream.read(byte_limit + 1)
    except BuildError:
        raise
    except OSError:
        raise BuildError(invalid_category) from None
    if len(raw) > byte_limit:
        raise BuildError(oversized_category)
    if len(raw) != size:
        raise BuildError(invalid_category)
    return raw


def _metadata_identity(path: Path) -> tuple[str, str]:
    metadata_file = path / "METADATA"
    if _is_reparse_or_symlink(metadata_file) or not metadata_file.is_file():
        raise BuildError("dependency_metadata_invalid")
    try:
        raw = _read_bounded_file(
            metadata_file,
            MAX_METADATA_BYTES,
            invalid_category="dependency_metadata_invalid",
            oversized_category="dependency_metadata_invalid",
        )
        text = raw.decode("utf-8", errors="strict")
    except (BuildError, UnicodeError):
        raise BuildError("dependency_metadata_invalid") from None
    names = [line[6:] for line in text.splitlines() if line.startswith("Name: ")]
    versions = [line[9:] for line in text.splitlines() if line.startswith("Version: ")]
    if len(names) != 1 or len(versions) != 1:
        raise BuildError("dependency_metadata_invalid")
    name, version = names[0], versions[0]
    if (
        len(name) > 128
        or len(version) > 128
        or not _NAME_VERSION.fullmatch(name)
        or not version
        or any(ch.isspace() for ch in version)
    ):
        raise BuildError("dependency_metadata_invalid")
    return _canonical_name(name), version


def _validate_pip_jmespath_launcher(root: Path, distribution_info: Path) -> None:
    launcher_dir = root / "bin"
    if not launcher_dir.exists():
        return
    if _is_reparse_or_symlink(launcher_dir) or not launcher_dir.is_dir():
        raise BuildError("dependency_launcher_invalid")
    try:
        children = list(launcher_dir.iterdir())
    except OSError:
        raise BuildError("dependency_launcher_invalid") from None
    if len(children) != 1 or children[0].name != "jp.py" or _is_reparse_or_symlink(children[0]) or not children[0].is_file():
        raise BuildError("dependency_launcher_invalid")
    launcher = children[0]
    try:
        raw = _read_bounded_file(
            launcher,
            8192,
            invalid_category="dependency_launcher_invalid",
            oversized_category="dependency_launcher_invalid",
        )
    except BuildError:
        raise BuildError("dependency_launcher_invalid") from None
    first_line, separator, body = raw.partition(b"\n")
    shebang = first_line.rstrip(b"\r")
    if (
        not separator
        or not re.fullmatch(rb"#![^\x00\r\n]{1,512}(?:python(?:\.exe)?|python[0-9.]*)", shebang, re.IGNORECASE)
        or body.replace(b"\r\n", b"\n") != _EXPECTED_JP_LAUNCHER_BODY
        or b"\r" in body.replace(b"\r\n", b"")
    ):
        raise BuildError("dependency_launcher_invalid")

    record_path = distribution_info / "RECORD"
    if _is_reparse_or_symlink(record_path) or not record_path.is_file():
        raise BuildError("dependency_launcher_invalid")
    try:
        record_raw = _read_bounded_file(
            record_path,
            MAX_METADATA_BYTES,
            invalid_category="dependency_launcher_invalid",
            oversized_category="dependency_launcher_invalid",
        )
        rows = list(csv.reader(record_raw.decode("utf-8", errors="strict").splitlines()))
    except (BuildError, UnicodeError, csv.Error):
        raise BuildError("dependency_launcher_invalid") from None
    launcher_rows = [row for row in rows if row and row[0].startswith("../../bin/")]
    if len(launcher_rows) != 1 or len(launcher_rows[0]) != 3 or launcher_rows[0][0] != "../../bin/jp.py":
        raise BuildError("dependency_launcher_invalid")
    digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
    if launcher_rows[0][1] != digest or launcher_rows[0][2] != str(len(raw)):
        raise BuildError("dependency_launcher_invalid")


def _validate_distribution_directory_name(directory: str, name: str, version: str) -> None:
    if not directory.endswith(".dist-info"):
        raise BuildError("dependency_distribution_invalid")
    identity = directory[: -len(".dist-info")]
    try:
        directory_name, directory_version = identity.rsplit("-", 1)
    except ValueError:
        raise BuildError("dependency_distribution_invalid") from None
    if _canonical_name(directory_name) != name or directory_version != version:
        raise BuildError("dependency_distribution_invalid")


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _collect_dependency_files(dependency_dir: Path) -> tuple[list[tuple[str, bytes]], int]:
    if _is_reparse_or_symlink(dependency_dir) or not dependency_dir.is_dir():
        raise BuildError("dependency_directory_invalid")
    root = dependency_dir.resolve(strict=True)
    try:
        children = list(root.iterdir())
    except OSError:
        raise BuildError("dependency_directory_invalid") from None
    if len(children) > MAX_ROOT_ENTRIES:
        raise BuildError("dependency_roots_invalid")

    package_seen: set[str] = set()
    distribution_seen: dict[str, str] = {}
    distribution_paths: dict[str, Path] = {}
    selected_roots: list[Path] = []
    for child in children:
        if _is_reparse_or_symlink(child):
            raise BuildError("dependency_symlink_rejected")
        name = child.name
        if name == "__pycache__" or name.endswith(".pyc"):
            continue
        if name == "bin":
            continue
        if name.casefold().endswith(".pth"):
            raise BuildError("dependency_path_file_rejected")
        if name in PACKAGE_ROOTS:
            if name in package_seen:
                raise BuildError("dependency_roots_invalid")
            expected_kind_dir = name != "six.py"
            if expected_kind_dir != child.is_dir() or (not expected_kind_dir and not child.is_file()):
                raise BuildError("dependency_roots_invalid")
            package_seen.add(name)
            selected_roots.append(child)
            continue
        if child.is_dir() and name.endswith(".dist-info"):
            distribution_name, version = _metadata_identity(child)
            _validate_distribution_directory_name(name, distribution_name, version)
            if distribution_name not in PINNED_DISTRIBUTIONS or distribution_name in distribution_seen:
                raise BuildError("dependency_distribution_invalid")
            if version != PINNED_DISTRIBUTIONS[distribution_name]:
                raise BuildError("dependency_version_invalid")
            distribution_seen[distribution_name] = version
            distribution_paths[distribution_name] = child
            selected_roots.append(child)
            continue
        raise BuildError("dependency_roots_invalid")

    if package_seen != PACKAGE_ROOTS or set(distribution_seen) != set(PINNED_DISTRIBUTIONS):
        raise BuildError("dependency_inventory_incomplete")
    _validate_pip_jmespath_launcher(root, distribution_paths["jmespath"])

    collected: list[tuple[str, bytes]] = []
    total = 0
    for package_root in selected_roots:
        if package_root.is_file():
            files: Iterable[Path] = (package_root,)
        else:
            walked: list[Path] = []
            visited = 0
            for current, directory_names, filenames in os.walk(package_root, topdown=True, followlinks=False):
                current_path = Path(current)
                visited += 1
                if visited > MAX_FILE_COUNT:
                    raise BuildError("dependency_file_count_exceeded")
                kept_dirs: list[str] = []
                for directory in sorted(directory_names):
                    directory_path = current_path / directory
                    if _is_reparse_or_symlink(directory_path):
                        raise BuildError("dependency_symlink_rejected")
                    visited += 1
                    if visited > MAX_FILE_COUNT:
                        raise BuildError("dependency_file_count_exceeded")
                    if directory == "__pycache__":
                        continue
                    kept_dirs.append(directory)
                directory_names[:] = kept_dirs
                for filename in sorted(filenames):
                    file_path = current_path / filename
                    if _is_reparse_or_symlink(file_path):
                        raise BuildError("dependency_symlink_rejected")
                    if filename.endswith(".pyc"):
                        continue
                    if filename.casefold().endswith(".pth"):
                        raise BuildError("dependency_path_file_rejected")
                    folded_name = filename.casefold()
                    if (
                        folded_name in _DENIED_BASENAMES
                        or folded_name == ".env"
                        or folded_name.startswith(".env.")
                        or folded_name.endswith((".key", ".p12", ".pfx"))
                    ):
                        raise BuildError("dependency_secret_file_rejected")
                    visited += 1
                    if visited > MAX_FILE_COUNT:
                        raise BuildError("dependency_file_count_exceeded")
                    walked.append(file_path)
                    if len(walked) > MAX_FILE_COUNT:
                        raise BuildError("dependency_file_count_exceeded")
            files = walked

        for file_path in files:
            if _is_reparse_or_symlink(file_path) or not file_path.is_file():
                raise BuildError("dependency_file_invalid")
            try:
                size = file_path.stat().st_size
            except OSError:
                raise BuildError("dependency_file_invalid") from None
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                raise BuildError("dependency_size_exceeded")
            data = _read_bounded_file(
                file_path,
                MAX_FILE_BYTES,
                invalid_category="dependency_file_invalid",
                oversized_category="dependency_size_exceeded",
            )
            if total + len(data) > MAX_TOTAL_BYTES:
                raise BuildError("dependency_size_exceeded")
            total += len(data)
            relative = file_path.relative_to(root).as_posix()
            if relative.startswith("/") or ".." in Path(relative).parts:
                raise BuildError("dependency_path_invalid")
            if len(relative) > 1024:
                raise BuildError("dependency_path_invalid")
            collected.append((relative, data))
            if len(collected) > MAX_FILE_COUNT:
                raise BuildError("dependency_file_count_exceeded")
    return collected, total


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _validate_output_path(output_path: Path, dependency_dir: Path, repository_root: Path) -> Path:
    try:
        output = output_path.resolve(strict=False)
        root = repository_root.resolve(strict=True)
        dependencies = dependency_dir.resolve(strict=True)
    except OSError:
        raise BuildError("output_path_invalid") from None
    if _inside(output, root) or _inside(output, dependencies) or output.exists():
        raise BuildError("output_path_invalid")
    if not output.parent.is_dir():
        raise BuildError("output_path_invalid")
    return output


def _app_files(repository_root: Path) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for archive_name, fixed_content in APP_MODULES:
        if fixed_content is not None:
            data = fixed_content
        else:
            source_path = repository_root / "src" / archive_name
            if _is_reparse_or_symlink(source_path) or not source_path.is_file():
                raise BuildError("shutdown_source_invalid")
            data = _read_bounded_file(
                source_path,
                MAX_FILE_BYTES,
                invalid_category="shutdown_source_invalid",
                oversized_category="shutdown_source_too_large",
            )
        files.append((archive_name, data))
    return files


def _validate_pinned_requirements(repository_root: Path) -> None:
    requirements_path = repository_root / "infra" / "aws" / "shutdown-requirements.txt"
    if _is_reparse_or_symlink(requirements_path) or not requirements_path.is_file():
        raise BuildError("shutdown_requirements_invalid")
    try:
        raw = _read_bounded_file(
            requirements_path,
            4096,
            invalid_category="shutdown_requirements_invalid",
            oversized_category="shutdown_requirements_invalid",
        )
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except (BuildError, UnicodeError):
        raise BuildError("shutdown_requirements_invalid") from None
    expected = [f"{name}=={version}" for name, version in sorted(PINNED_DISTRIBUTIONS.items())]
    if lines != expected:
        raise BuildError("shutdown_requirements_invalid")


def build_archive(dependency_dir: Path, output_path: Path) -> BuildSummary:
    """Create a deterministic external ZIP from the exact SDK stage and two modules."""
    dependency_dir = Path(dependency_dir)
    output_path = Path(output_path)
    repository_root = _repository_root()
    target = _validate_output_path(output_path, dependency_dir, repository_root)
    _validate_pinned_requirements(repository_root)
    dependency_files, dependency_size = _collect_dependency_files(dependency_dir)
    app_files = _app_files(repository_root)
    if dependency_size + sum(len(data) for _, data in app_files) > MAX_TOTAL_BYTES:
        raise BuildError("archive_content_too_large")
    entries = sorted(dependency_files + app_files, key=lambda item: item[0])
    if len(entries) > MAX_FILE_COUNT:
        raise BuildError("archive_file_count_exceeded")
    names = [name for name, _ in entries]
    if len(set(names)) != len(names):
        raise BuildError("archive_path_collision")

    import io

    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        zip_bytes = buffer.getvalue()
        if len(zip_bytes) > MAX_TOTAL_BYTES:
            raise BuildError("archive_content_too_large")
        with target.open("xb") as output:
            output.write(zip_bytes)
    except OSError:
        raise BuildError("archive_write_failed") from None
    return BuildSummary(
        zip_bytes=len(zip_bytes),
        sha256=hashlib.sha256(zip_bytes).hexdigest(),
        dependencies_valid=True,
        minimal_package_init=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependency-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = build_archive(args.dependency_dir, args.output)
    except Exception:
        print(json.dumps({"success": False, "category": "shutdown_package_build_failed"}))
        return 1
    print(json.dumps({
        "success": True,
        "category": "shutdown_package_built",
        "zip_bytes": summary.zip_bytes,
        "sha256": summary.sha256,
        "dependencies_valid": summary.dependencies_valid,
        "minimal_package_init": summary.minimal_package_init,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
