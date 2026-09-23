import pytest

from mapit.config import RuntimeConfig, bundle_urls, discover_runtime_config, extract_runtime_config
from mapit.config import MapitConfig


def test_extracts_amplify_fields_and_hosts_from_bundles():
    html = '<script src="/assets/vendor.js"></script><script src="/assets/main-abc.js"></script>'
    bundle = """Amplify.configure({Auth:{Cognito:{userPoolId:'eu-west-1_TEST',userPoolClientId:'client-test',identityPoolId:'eu-west-1:identity-test'}},region:'eu-west-1'}); const a='https://core.prod.mapit.me'; const b='https://geo.prod.mapit.me';"""
    result = discover_runtime_config(html, {"main": bundle})
    assert result.region == "eu-west-1"
    assert result.user_pool_id == "eu-west-1_TEST"
    assert result.user_pool_client_id == "client-test"
    assert result.identity_pool_id == "eu-west-1:identity-test"
    assert result.core_api_url == "https://core.prod.mapit.me"
    assert result.geo_api_url == "https://geo.prod.mapit.me"


def test_discovery_overrides_win_and_bundle_order_is_stable():
    assert bundle_urls('<script src="/assets/vendor.js"></script><script src="/assets/main-x.js"></script>')[0].endswith("main-x.js")
    result = discover_runtime_config(
        "",
        {"b": "'https://core.prod.mapit.me'"},
        overrides=RuntimeConfig(core_api_url="https://core.override.mapit.me"),
    )
    assert result.core_api_url == "https://core.override.mapit.me"


def test_bundle_urls_collects_preloads_dynamic_imports_and_deduplicates():
    html = """
    <script src="/assets/vendor.js"></script>
    <link rel="modulepreload" href="/assets/chunk.js">
    <link rel="preload" as="script" href="/assets/main-hash.js">
    <link rel="preload" as="style" href="/assets/not-script.js">
    <script type="module">import("/assets/chunk.js"); import('/assets/lazy.js')</script>
    <script src="https://evil.example/assets/evil.js"></script>
    """
    assert bundle_urls(html) == [
        "https://app.mapit.me/assets/main-hash.js",
        "https://app.mapit.me/assets/chunk.js",
        "https://app.mapit.me/assets/lazy.js",
        "https://app.mapit.me/assets/vendor.js",
    ]


def test_config_repr_does_not_expose_password():
    rendered = repr(MapitConfig(email="person@example.test", password="password-test"))
    assert "password-test" not in rendered


@pytest.mark.parametrize("bad", [
    "http://core.prod.mapit.me",
    "https://core.prod.mapit.me:8443",
    "https://user:pass@core.prod.mapit.me",
    "https://core.prod.mapit.me.evil.test",
    "https://evilcore.prod.mapit.me",
    "https://geo.prod.mapit.me/v1",
    "https://geo.prod.mapit.me?x=1",
])
def test_api_endpoint_overrides_fail_closed(bad):
    with pytest.raises(ValueError):
        MapitConfig(core_api_url=bad)


def test_discovered_malicious_endpoint_fails_closed():
    with pytest.raises(ValueError):
        extract_runtime_config("const api='https://core.prod.mapit.me.evil.test';")
