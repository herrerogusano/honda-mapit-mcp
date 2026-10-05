"""Print redacted public runtime discovery results (never credentials)."""

from __future__ import annotations

import json

from mapit.config import fetch_public_runtime_config


def main() -> None:
    runtime = fetch_public_runtime_config()
    print(json.dumps({
        "region": runtime.region,
        "user_pool_id": "<discovered>" if runtime.user_pool_id else None,
        "user_pool_client_id": "<discovered>" if runtime.user_pool_client_id else None,
        "identity_pool_id": "<discovered>" if runtime.identity_pool_id else None,
        "core_api_url": runtime.core_api_url,
        "geo_api_url": runtime.geo_api_url,
    }, indent=2))


if __name__ == "__main__":
    main()

