import pytest

from mapit.config import RuntimeConfig, RuntimeConfigDiscoveryError, bundle_urls, discover_runtime_config, extract_runtime_config, fetch_public_runtime_config
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


def test_fetcher_enforces_html_and_bundle_byte_limits_before_parsing(monkeypatch):
    import mapit.config as config_module
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_HTML_BYTES", 8)
    with pytest.raises(RuntimeConfigDiscoveryError) as caught:
        fetch_public_runtime_config(fetcher=lambda url, timeout: "x" * 9)
    assert caught.value.category == "discovery_size_limit_exceeded"
    assert "https://" not in str(caught.value)

    monkeypatch.setattr(config_module, "MAX_DISCOVERY_HTML_BYTES", 1024)
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_BUNDLE_BYTES", 4)
    calls = []
    def fetcher(url, timeout):
        calls.append((url, timeout))
        return '<script src="/one.js"></script>' if len(calls) == 1 else "12345"
    with pytest.raises(RuntimeConfigDiscoveryError):
        fetch_public_runtime_config(fetcher=fetcher)
    assert len(calls) == 2


def test_bundle_failure_fallback_counts_attempts_and_hard_bundle_limit_propagates(monkeypatch):
    import mapit.config as config_module
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_BUNDLES", 1)
    html = '<script src="/a.js"></script><script src="/b.js"></script>'
    calls = []
    def fetcher(url, timeout):
        calls.append(url)
        if len(calls) == 1:
            return html
        raise OSError("secret url detail")
    with pytest.raises(RuntimeConfigDiscoveryError) as caught:
        fetch_public_runtime_config(fetcher=fetcher)
    assert caught.value.category == "discovery_bundle_limit_exceeded"
    assert len(calls) == 2  # Failed first bundle attempt still consumes a slot.

    monkeypatch.setattr(config_module, "MAX_DISCOVERY_BUNDLES", 32)
    def fallback_fetcher(url, timeout):
        if url.endswith("/"):
            return html
        raise OSError("secret url detail")
    result = fetch_public_runtime_config(fetcher=fallback_fetcher)
    assert result.core_api_url == "https://core.prod.mapit.me"


def test_discovery_cooperatively_checks_elapsed_budget_and_passes_remaining_timeout(monkeypatch):
    import mapit.config as config_module
    clock = iter([0.0, 0.0, 61.0])
    monkeypatch.setattr(config_module.time, "monotonic", lambda: next(clock))
    observed = []
    def fetcher(url, timeout):
        observed.append(timeout)
        return ""
    with pytest.raises(RuntimeConfigDiscoveryError) as caught:
        fetch_public_runtime_config(fetcher=fetcher)
    assert caught.value.category == "discovery_budget_exceeded"
    assert observed == [20.0]


def test_discovery_aggregate_ceiling_stops_before_config_extraction(monkeypatch):
    import mapit.config as config_module
    html = '<script src="/a.js"></script>'
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_HTML_BYTES", 1024)
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_BUNDLE_BYTES", 1024)
    monkeypatch.setattr(config_module, "MAX_DISCOVERY_TOTAL_BYTES", len(html.encode()) + 4)
    calls = []
    def fetcher(url, timeout):
        calls.append(url)
        return html if len(calls) == 1 else "12345"
    with pytest.raises(RuntimeConfigDiscoveryError) as caught:
        fetch_public_runtime_config(fetcher=fetcher)
    assert caught.value.category == "discovery_size_limit_exceeded"
    assert len(calls) == 2


def test_discovery_reduces_next_fetch_timeout_to_budget_remaining(monkeypatch):
    import mapit.config as config_module
    clock = iter([0.0, 0.0, 50.0, 50.0, 51.0])
    monkeypatch.setattr(config_module.time, "monotonic", lambda: next(clock))
    observed = []
    def fetcher(url, timeout):
        observed.append(timeout)
        return '<script src="/bundle.js"></script>' if len(observed) == 1 else ""
    fetch_public_runtime_config(timeout=55.0, fetcher=fetcher)
    assert observed == [55.0, 10.0]


def test_default_discovery_checks_deadline_after_each_body_chunk(monkeypatch):
    import mapit.config as config_module
    clock = [0.0]
    monkeypatch.setattr(config_module.time, "monotonic", lambda: clock[0])
    body = b'<script src="/bundle.js"></script>'
    reads = []
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read1(self, size):
            reads.append(size)
            clock[0] = 61.0
            return body[:5]
    class Opener:
        def open(self, request, timeout):
            return Response()
    monkeypatch.setattr(config_module, "open_direct", lambda request, timeout: Opener().open(request, timeout))
    with pytest.raises(RuntimeConfigDiscoveryError) as caught:
        fetch_public_runtime_config()
    assert caught.value.category == "discovery_budget_exceeded"
    assert len(reads) == 1
