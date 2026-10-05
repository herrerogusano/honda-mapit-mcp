import json
from types import SimpleNamespace
import pytest

from mapit.agent import AgentAnswer
from mapit.codex_cli_backend import CodexCliResult
from mapit.telegram_bot import BotApiTransport, TelegramBotError, TelegramBotPoller, TelegramIncomingUpdate
from mapit.telegram_credentials import TelegramCredentials
from scripts.smoke_telegram_live import run_live_smoke
from scripts.telegram_setup_gui import save_telegram_token


class Response:
    def __init__(self, value):
        self.value = value
        self.closed = False
        self.read_once = False
    def read(self, limit):
        if self.read_once:
            return b""
        self.read_once = True
        return json.dumps(self.value).encode()
    def close(self):
        self.closed = True


def test_bot_api_transport_bounded_calls_and_safe_parsing():
    calls = []
    responses = []
    def opener(request, timeout):
        method = request.full_url.rsplit("/", 1)[-1]
        calls.append((method, timeout, json.loads(request.data)))
        if method == "getMe":
            response = Response({"ok": True, "result": {"is_bot": True}})
            responses.append(response)
            return response
        if method == "getWebhookInfo":
            response = Response({"ok": True, "result": {"url": ""}})
            responses.append(response)
            return response
        if method == "getUpdates":
            response = Response({"ok": True, "result": []})
            responses.append(response)
            return response
        response = Response({"ok": True, "result": True})
        responses.append(response)
        return response
    transport = BotApiTransport("123456789:ABCDEFGHIJKLMNOPQRST", opener=opener)
    assert transport.get_me() is True
    assert transport.get_webhook_info() is True
    assert transport.get_updates(timeout_seconds=25) == ()
    transport.send_message(20, "safe")
    assert [entry[0] for entry in calls] == ["getMe", "getWebhookInfo", "getUpdates", "sendMessage"]
    assert calls[2][2] == {"limit": 1, "timeout": 25, "allowed_updates": ["message"]}
    assert all(response.closed for response in responses)


def test_transport_rejects_invalid_token_or_endpoint():
    with pytest.raises(Exception):
        BotApiTransport("not-a-token")
    with pytest.raises(Exception):
        BotApiTransport("123456789:ABCDEFGHIJKLMNOPQRST", api_base="https://example.invalid")


def test_default_telegram_path_is_direct_bounded_and_does_not_retry(monkeypatch):
    from mapit import http_transport
    calls = []
    class Response:
        status = 302
        def close(self):
            pass
    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            return Response()
    monkeypatch.setattr(http_transport, "direct_opener", lambda: Opener())
    transport = BotApiTransport("123456789:ABCDEFGHIJKLMNOPQRST")
    with pytest.raises(TelegramBotError) as caught:
        transport.send_message(7, "once")
    assert caught.value.category == "transport_failed"
    assert len(calls) == 1


def test_telegram_default_path_maps_oversized_response_safely(monkeypatch):
    from mapit import http_transport
    class Response:
        def __init__(self):
            self.remaining = b"x" * (1024 * 1024 + 1)
        def read1(self, size):
            result, self.remaining = self.remaining[:size], self.remaining[size:]
            return result
        def close(self):
            pass
    class Opener:
        def open(self, request, timeout):
            return Response()
    monkeypatch.setattr(http_transport, "direct_opener", lambda: Opener())
    transport = BotApiTransport("123456789:ABCDEFGHIJKLMNOPQRST")
    with pytest.raises(TelegramBotError) as caught:
        transport.get_me()
    assert caught.value.category == "response_too_large"


class FakeStore:
    def load(self):
        return TelegramCredentials("secret-token", frozenset({(10, 20)}))


class FakeTransport:
    def __init__(self, token):
        self.token = token
        self.sent = []
    def get_me(self):
        return True
    def get_updates(self, *, timeout_seconds, offset=None):
        return ()
    def get_webhook_info(self):
        return True
    def send_message(self, chat_id, text):
        self.sent.append((chat_id, text))


def test_poller_reads_store_only_and_is_bounded():
    transports = []
    def factory(token):
        item = FakeTransport(token)
        transports.append(item)
        return item
    backend = object()
    result = TelegramBotPoller(FakeStore(), backend, transport_factory=factory).poll_once()
    assert result.success is True and result.category == "success"
    assert transports[0].token == "secret-token"


def test_live_smoke_requires_both_explicit_flags_and_never_leaks_values():
    calls = []
    result = run_live_smoke(FakeStore(), transport_factory=lambda token: calls.append(token) or FakeTransport(token))
    assert result == {"success": False, "category": "confirmation_required"}
    assert calls == []


def test_setup_helper_saves_token_only_and_returns_challenge_for_gui():
    class Store:
        def __init__(self):
            self.saved = None
        def save_token(self, token, *, challenge):
            self.saved = (token, challenge)
    store = Store()
    result = save_telegram_token(store, "123456789:ABCDEFGHIJKLMNOPQRST")
    assert result["success"] is True
    assert result["category"] == "saved"
    assert isinstance(result["challenge"], str) and len(result["challenge"]) >= 32
    assert store.saved[0] not in repr({"success": result["success"], "category": result["category"]})


class OnboardingStore:
    def __init__(self):
        self.token = "123456789:ABCDEFGHIJKLMNOPQRST"
        self.challenge = "A" * 43
        self.pairs = []
        self.deleted = []
    def load_token(self):
        return self.token
    def load_challenge(self):
        return self.challenge
    def save_allowlist(self, pair):
        self.pairs.append(pair)
    def delete_challenge(self, challenge):
        self.deleted.append(challenge)


class OnboardingTransport:
    def __init__(self, envelope, *, webhook=True, send_error=False):
        self.envelope = envelope
        self.webhook = webhook
        self.send_error = send_error
        self.sent = []
    def get_me(self):
        return True
    def get_webhook_info(self):
        return self.webhook
    def get_updates(self, *, timeout_seconds, offset=None):
        return (self.envelope,)
    def send_message(self, chat_id, text):
        if self.send_error:
            raise TelegramBotError("send_failed")
        self.sent.append((chat_id, text))


def _onboarding_envelope(*, text="/start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", is_bot=False, chat_type="private"):
    update = SimpleNamespace(user_id=10, chat_id=20, chat_type=chat_type, text=text)
    return TelegramIncomingUpdate(update, is_bot)


def test_onboarding_requires_exact_private_start_non_bot_and_then_sends_once():
    store = OnboardingStore()
    transport = OnboardingTransport(_onboarding_envelope())
    result = run_live_smoke(store, transport_factory=lambda token: transport, allow_get_updates=True, allow_send_message=True)
    assert result["success"] is True
    assert store.pairs == [(10, 20)]
    assert store.deleted == [store.challenge]
    assert transport.sent == [(20, "MAPIT smoke check")]


def test_onboarding_rejects_group_text_bot_and_webhook_without_save_or_send():
    for envelope, webhook, category in (
        (_onboarding_envelope(chat_type="group"), True, "onboarding_update_invalid"),
        (_onboarding_envelope(text="/start now"), True, "onboarding_update_invalid"),
        (_onboarding_envelope(is_bot=True), True, "onboarding_update_invalid"),
        (_onboarding_envelope(), False, "webhook_active"),
    ):
        store = OnboardingStore()
        transport = OnboardingTransport(envelope, webhook=webhook)
        result = run_live_smoke(store, transport_factory=lambda token, item=transport: item, allow_get_updates=True, allow_send_message=True)
        assert result["category"] == category
        assert store.pairs == []
        assert transport.sent == []


def test_send_failure_is_safe_and_allowlist_write_is_not_retried():
    store = OnboardingStore()
    transport = OnboardingTransport(_onboarding_envelope(), send_error=True)
    result = run_live_smoke(store, transport_factory=lambda token: transport, allow_get_updates=True, allow_send_message=True)
    assert result == {"success": False, "category": "send_failed"}
    assert store.pairs == [(10, 20)]
