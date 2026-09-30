"""Export installed third-party pins from a clean environment for strict audit.

The first-party project is reviewed as source, not queried as a PyPI package.
No direct URLs, local paths or environment variables enter the manifest.
"""

from __future__ import annotations

import argparse
import json
import re
from importlib import metadata
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import Version


def installed_pins(distributions=None) -> tuple[str, ...]:
    packages = metadata.distributions() if distributions is None else distributions
    pins: dict[str, str] = {}
    project_seen = False
    for index, package in enumerate(packages):
        if index >= 200:
            raise ValueError("audit_inventory_invalid")
        name = package.metadata.get("Name")
        if not isinstance(name, str) or len(name) > 128 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError("audit_inventory_invalid")
        name = canonicalize_name(name)
        if name == "mapit-client":
            project_seen = True
            continue
        version = str(Version(package.version))
        if len(version) > 128 or name in pins and pins[name] != version:
            raise ValueError("audit_inventory_invalid")
        pins[name] = version
    if not project_seen or not pins:
        raise ValueError("audit_inventory_invalid")
    return tuple(f"{name}=={version}" for name, version in sorted(pins.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        pins = installed_pins()
        args.output.write_text("\n".join(pins) + "\n", encoding="utf-8")
    except Exception:
        print(json.dumps({"success": False, "category": "audit_inventory_invalid"}))
        return 1
    print(json.dumps({"success": True, "category": "audit_inventory_exported", "packages": len(pins)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
