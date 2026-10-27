"""Build the single deterministic ZIP shared by both multiuser Lambdas.

Both ``mapit.multiuser_entrypoint.handler`` and
``mapit.multiuser_identity.handler`` run from the same archive: the 28
hash-locked ARM wheels from ``infra/aws/runtime-requirements.txt`` plus the
``mapit`` source modules reachable by static import analysis from the five
multiuser root modules. The archive embeds no private configuration (that is
passed as CloudFormation parameters) and performs no network or AWS access.
Optional geography support adds the locked numpy/shapely wheels and the two
hash-pinned public area assets.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scripts import build_aws_dev_runtime as dev_builder
from scripts import build_aws_prod_runtime as prod_builder

ROOT_MODULES = (
    "multiuser_common.py",
    "multiuser_runtime.py",
    "multiuser_entrypoint.py",
    "multiuser_identity.py",
    "multiuser_pages.py",
)
HANDLER_MODULES = ("multiuser_entrypoint", "multiuser_identity")
MAX_SOURCE_MODULES = 64


class MultiuserBuildError(ValueError):
    """Closed build failure without paths or source values."""


@dataclass(frozen=True)
class MultiuserBuildSummary:
    zip_bytes: int
    sha256: str
    wheel_count: int
    archive_entries: int
    source_modules: tuple[str, ...]
    geography: bool


def _imported_mapit_modules(tree: ast.AST) -> set[str]:
    """Top-level ``mapit`` submodule names imported anywhere in ``tree``."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1:
                if node.module:
                    found.add(node.module.split(".")[0])
                else:
                    found.update(alias.name.split(".")[0] for alias in node.names)
            elif node.level == 0 and node.module:
                parts = node.module.split(".")
                if parts[0] == "mapit":
                    if len(parts) > 1:
                        found.add(parts[1])
                    else:
                        found.update(alias.name.split(".")[0] for alias in node.names)
            elif node.level > 1:
                raise MultiuserBuildError("runtime_source_import_unsupported")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "mapit" and len(parts) > 1:
                    found.add(parts[1])
    return found


def source_module_inventory(source_root: Path, roots: tuple[str, ...] = ROOT_MODULES) -> tuple[str, ...]:
    """Transitive closure of ``mapit`` modules imported by ``roots`` (file names, sorted).

    Lazy imports inside functions are included on purpose: the archive must
    contain every module a handler may load at runtime.
    """
    pending = list(roots)
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        path = source_root / name
        if dev_builder._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise MultiuserBuildError("runtime_source_invalid")
        seen.add(name)
        if len(seen) > MAX_SOURCE_MODULES:
            raise MultiuserBuildError("runtime_source_inventory_too_large")
        try:
            raw = dev_builder._read_bounded(path, dev_builder.MAX_SOURCE_BYTES, "runtime_source_invalid")
            tree = ast.parse(raw, filename=name)
        except (dev_builder.BuildError, SyntaxError, ValueError):
            raise MultiuserBuildError("runtime_source_invalid") from None
        for module in _imported_mapit_modules(tree):
            if module == "__init__":
                continue
            candidate = f"{module}.py"
            if not (source_root / candidate).is_file():
                # e.g. `from . import data` style package resources are not modules.
                if (source_root / module).is_dir():
                    continue
                raise MultiuserBuildError("runtime_source_missing")
            pending.append(candidate)
    return tuple(sorted(seen))


def source_entries(repo: Path, *, geography: bool = False) -> tuple[list[tuple[str, bytes]], tuple[str, ...]]:
    source_root = repo / "src" / "mapit"
    if dev_builder._has_symlink_or_reparse_ancestor(source_root) or not source_root.is_dir():
        raise MultiuserBuildError("runtime_source_invalid")
    modules = source_module_inventory(source_root)
    entries = [("mapit/__init__.py", b"")]
    for module in modules:
        raw = dev_builder._read_bounded(source_root / module, dev_builder.MAX_SOURCE_BYTES, "runtime_source_invalid")
        entries.append((f"mapit/{module}", raw))
    if geography:
        for asset_name, expected in (
            (prod_builder.GEOGRAPHY_ASSET, prod_builder.GEOGRAPHY_ASSET_SHA256),
            (prod_builder.GEOGRAPHY_AMB_ASSET, prod_builder.GEOGRAPHY_AMB_ASSET_SHA256),
        ):
            asset = source_root / asset_name
            if dev_builder._has_symlink_or_reparse_ancestor(asset) or not asset.is_file():
                raise MultiuserBuildError("geography_asset_invalid")
            raw = dev_builder._read_bounded(asset, 1024 * 1024, "geography_asset_invalid")
            if hashlib.sha256(raw).hexdigest() != expected:
                raise MultiuserBuildError("geography_asset_invalid")
            entries.append((f"mapit/{asset_name}", raw))
    return entries, modules


def deterministic_zip(entries: list[tuple[str, bytes]]) -> bytes:
    seen: set[str] = set()
    total = 0
    for name, data in entries:
        folded = name.casefold()
        if folded in seen:
            raise MultiuserBuildError("archive_path_collision")
        seen.add(folded)
        if len(data) > dev_builder.MAX_ENTRY_BYTES or total + len(data) > dev_builder.MAX_TOTAL_BYTES:
            raise MultiuserBuildError("archive_content_too_large")
        total += len(data)
    if len(entries) > dev_builder.MAX_FILE_COUNT:
        raise MultiuserBuildError("archive_file_count_exceeded")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
                         strict_timestamps=True) as archive:
        for name, data in sorted(entries, key=lambda item: item[0]):
            info = zipfile.ZipInfo(name, date_time=dev_builder.ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    result = buffer.getvalue()
    if len(result) > dev_builder.MAX_ARCHIVE_BYTES:
        raise MultiuserBuildError("archive_compressed_size_exceeded")
    return result


def build_multiuser_archive(
    wheel_dir: Path,
    output_path: Path,
    *,
    geography_wheel_dir: Path | None = None,
) -> MultiuserBuildSummary:
    """Write the ZIP to a new file outside the repository/OneDrive."""
    repo = dev_builder._repo_root()
    if dev_builder._is_reparse_or_symlink(repo) or not repo.is_dir():
        raise MultiuserBuildError("repository_invalid")
    wheel_root = dev_builder._validate_external_wheel_dir(Path(wheel_dir), repo)
    target = Path(output_path)
    if target.exists() or target.is_symlink() or dev_builder._has_symlink_or_reparse_ancestor(target.parent):
        raise MultiuserBuildError("output_path_invalid")
    resolved = target.resolve(strict=False)
    if (
        dev_builder._inside(resolved, repo.resolve())
        or dev_builder._inside(resolved, wheel_root)
        or any(dev_builder._is_onedrive_component(part) for part in resolved.parts)
        or not resolved.parent.is_dir()
    ):
        raise MultiuserBuildError("output_path_invalid")
    lock = dev_builder._read_lock(repo)
    wheel_files = dev_builder._wheel_file_inventory(wheel_root, lock)
    geography = geography_wheel_dir is not None
    if geography:
        extra_root = dev_builder._validate_external_wheel_dir(Path(geography_wheel_dir), repo)
        if dev_builder._inside(resolved, extra_root):
            raise MultiuserBuildError("output_path_invalid")
        extra_lock = prod_builder._geography_lock(repo)
        wheel_files = [*wheel_files, *dev_builder._wheel_file_inventory(extra_root, extra_lock)]
        lock = {**lock, **extra_lock}
    wheel_entries = dev_builder._unpack_wheels(wheel_files, lock)
    sources, modules = source_entries(repo, geography=geography)
    entries = [*wheel_entries, *sources]
    archive = deterministic_zip(entries)
    try:
        with resolved.open("xb") as stream:
            stream.write(archive)
    except OSError:
        raise MultiuserBuildError("archive_write_failed") from None
    return MultiuserBuildSummary(
        zip_bytes=len(archive), sha256=hashlib.sha256(archive).hexdigest(),
        wheel_count=len(wheel_files), archive_entries=len(entries),
        source_modules=modules, geography=geography,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--geography-wheel-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = build_multiuser_archive(args.wheel_dir, args.output,
                                          geography_wheel_dir=args.geography_wheel_dir)
    except (MultiuserBuildError, dev_builder.BuildError, prod_builder.ProdBuildError) as exc:
        print(json.dumps({"success": False, "category": str(exc)}))
        return 1
    print(json.dumps({"success": True, "sha256": summary.sha256, "zip_bytes": summary.zip_bytes,
                      "wheel_count": summary.wheel_count, "source_modules": len(summary.source_modules),
                      "geography": summary.geography}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["HANDLER_MODULES", "ROOT_MODULES", "MultiuserBuildError", "MultiuserBuildSummary",
           "build_multiuser_archive", "deterministic_zip", "source_entries", "source_module_inventory"]
