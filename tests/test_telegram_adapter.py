from __future__ import annotations

import asyncio

from mapit.agent import AgentAnswer
from mapit.codex_cli_backend import CodexCliResult
from mapit.telegram_adapter import TelegramAccessPolicy, TelegramAdapter, TelegramUpdate, format_agent_answer, is_channel_safe_text


def update(*, update_id=1, user_id=10, chat_id=20, chat_type="private", text="status"):
    return {"update_id": update_id, "user_id": user_id, "chat_id": chat_id, "chat_type": chat_type, "text": text}


class FakeBackend:
    def __init__(self, result):
        self.result = result
        self.questions = []
        self.active = 0
        self.max_active = 0
        self.started = []

    async def ask(self, question):
        self.questions.append(question)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.append(question)
        await asyncio.sleep(0)
        self.active -= 1
        return self.result


class FakeSender:
    def __init__(self):
        self.messages = []

    async def send_message(self, chat_id, text):
        self.messages.append((chat_id, text))


def adapter(result=None):
    backend = FakeBackend(result or CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), ("get_vehicle_status",), "success"))
    sender = FakeSender()
    return TelegramAdapter(TelegramAccessPolicy({(10, 20)}), backend, sender), backend, sender


def run(coro):
    return asyncio.run(coro)


def test_private_allowlisted_update_calls_backend_and_fake_sender_once():
    target, backend, sender = adapter()
    result = run(target.process_update(update()))
    assert result.success is True and result.sent is True
    assert backend.questions == ["status"]
    assert sender.messages == [(20, "ok")]
    assert "20" not in repr(result)


def test_group_or_wrong_pair_is_rejected_without_calls():
    target, backend, sender = adapter()
    for raw in (update(chat_type="group"), update(user_id=99), update(chat_id=99)):
        result = run(target.process_update(raw))
        assert result.category in {"malformed_update", "unauthorized"}
    assert backend.questions == []
    assert sender.messages == []


def test_empty_command_oversize_and_malformed_never_call_backend():
    target, backend, sender = adapter()
    for raw, expected in (
        (update(text=""), "empty_message"),
        (update(text="   "), "empty_message"),
        (update(text="/start"), "command_ignored"),
        (update(text="x" * 4097), "oversize_message"),
        ({"update_id": "bad"}, "malformed_update"),
    ):
        result = run(target.process_update(raw))
        assert result.success is False and result.category == expected
    assert backend.questions == []
    assert sender.messages == []


def test_duplicate_update_is_suppressed_in_memory():
    target, backend, sender = adapter()
    assert run(target.process_update(update(update_id=4))).success is True
    duplicate = run(target.process_update(update(update_id=4)))
    assert duplicate.category == "duplicate_update"
    assert len(backend.questions) == 1
    assert len(sender.messages) == 1


def test_backend_error_and_invalid_output_do_not_send():
    failure = CodexCliResult(False, None, (), "process_failed")
    target, backend, sender = adapter(failure)
    assert run(target.process_update(update())).category == "backend_failed"
    assert sender.messages == []


def test_backend_failure_releases_reservation_but_sender_failure_keeps_it():
    target, backend, sender = adapter(CodexCliResult(False, None, (), "process_failed"))
    assert run(target.process_update(update(update_id=41))).category == "backend_failed"
    backend.result = CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), ("get_vehicle_status",), "success")
    assert run(target.process_update(update(update_id=41))).success is True

    class FailingSender(FakeSender):
        async def send_message(self, chat_id, text):
            raise RuntimeError("private")

    backend = FakeBackend(CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), ("get_vehicle_status",), "success"))
    failing = TelegramAdapter(TelegramAccessPolicy({(10, 20)}), backend, FailingSender())
    assert run(failing.process_update(update(update_id=42))).category == "sender_failed"
    assert run(failing.process_update(update(update_id=42))).category == "duplicate_update"


def test_backend_cancellation_before_send_releases_reservation():
    class CancellingBackend:
        def __init__(self):
            self.calls = 0

        async def ask(self, question):
            self.calls += 1
            if self.calls == 1:
                raise asyncio.CancelledError()
            return CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), ("get_vehicle_status",), "success")

    backend = CancellingBackend()
    target = TelegramAdapter(TelegramAccessPolicy({(10, 20)}), backend, FakeSender())
    try:
        run(target.process_update(update(update_id=43)))
    except asyncio.CancelledError:
        pass
    assert run(target.process_update(update(update_id=43))).success is True


def test_backend_result_boundary_is_fail_closed():
    target, backend, sender = adapter(CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), (), "success"))
    assert run(target.process_update(update(update_id=51))).category == "backend_invalid"
    backend.result = CodexCliResult(True, AgentAnswer(answer="ok", caveats=[], needs_clarification=False), ("get_vehicle_status",), "not-success")
    assert run(target.process_update(update(update_id=52))).category == "backend_failed"
    backend.result = CodexCliResult(True, AgentAnswer(answer="need range", caveats=[], needs_clarification=True), (), "success")
    assert run(target.process_update(update(update_id=53))).success is True

    too_long = CodexCliResult(True, AgentAnswer(answer="x" * 4096, caveats=["more"], needs_clarification=False), (), "success")
    target, backend, sender = adapter(too_long)
    assert run(target.process_update(update(update_id=8))).category == "output_too_long"
    assert sender.messages == []


def test_answer_format_includes_caveats_and_clarification_with_plain_text_bound():
    text = format_agent_answer(AgentAnswer(answer="Need a date.", caveats=["range required"], needs_clarification=True))
    assert text == "Need a date.\nCaveats: range required\nClarification required."
    assert len(text) <= 4096


def test_channel_safe_gate_rejects_identifiers_coordinates_and_tokens_but_allows_normal_text():
    assert is_channel_safe_text("Vehicle checked on 2026-09-29; distance 12.5 km.")
    for unsafe in (
        "id 550e8400-e29b-41d4-a716-446655440000",
        "VIN 1HGCM82633A004352",
        "location 40.4168, -3.7038",
        "location 40,4168 -3,7038",
        "latitude: 40.4168, longitude: -3.7038",
        "lat=40,4168 lon=-3,7038",
        '{"lat":40.4168,"lng":-3.7038}',
        "internal 123456789012",
        "token eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "open https://example.invalid/?sig=private",
        "token=private-value",
        "Authorization: Bearer private-value",
        "lat is withheld",
        "longitude is withheld",
        "access_key=private-value",
        "client-secret: private-value",
        "refresh_token private-value",
        "id-token private-value",
        "api_token private-value",
    ):
        assert not is_channel_safe_text(unsafe)


def test_access_policy_none_and_non_iterable_fail_closed():
    for value in (None, 1):
        try:
            TelegramAccessPolicy(value)
        except ValueError as exc:
            assert str(exc) == "invalid access policy"
        else:
            raise AssertionError("invalid policy accepted")


def test_clarification_rejects_unknown_tool_names():
    target, backend, sender = adapter(
        CodexCliResult(True, AgentAnswer(answer="Need a range.", caveats=[], needs_clarification=True), ("unknown",), "success")
    )
    assert run(target.process_update(update(update_id=61))).category == "backend_invalid"


def test_unsafe_channel_output_never_calls_sender():
    sender = FakeSender()
    backend = FakeBackend(
        CodexCliResult(
            True,
            AgentAnswer(answer="See https://example.invalid/private", caveats=[], needs_clarification=False),
            ("get_vehicle_status",),
            "success",
        )
    )
    target = TelegramAdapter(TelegramAccessPolicy({(10, 20)}), backend, sender)
    assert run(target.process_update(update(update_id=62))).category == "unsafe_output"
    assert sender.messages == []


def test_tester_repros_are_sender_free():
    repros = (
        "lat is withheld",
        "longitude is withheld",
        "access_key=private-value",
        "client-secret: private-value",
        "refresh_token private-value",
        "id-token private-value",
        "api_token private-value",
    )
    sender = FakeSender()
    for update_id, answer in enumerate(repros, 70):
        backend = FakeBackend(
            CodexCliResult(True, AgentAnswer(answer=answer, caveats=[], needs_clarification=False), ("get_vehicle_status",), "success")
        )
        target = TelegramAdapter(TelegramAccessPolicy({(10, 20)}), backend, sender)
        assert run(target.process_update(update(update_id=update_id))).category == "unsafe_output"
    assert sender.messages == []


def test_processing_is_sequential_under_concurrency():
    target, backend, sender = adapter()

    async def exercise():
        return await asyncio.gather(
            target.process_update(update(update_id=11, text="first")),
            target.process_update(update(update_id=12, text="second")),
        )

    results = run(exercise())
    assert all(item.success for item in results)
    assert backend.max_active == 1
    assert len(sender.messages) == 2


def test_nested_synthetic_telegram_shape_is_projected_without_raw_retention():
    target, backend, sender = adapter()
    raw = {"update_id": 30, "message": {"from": {"id": 10}, "chat": {"id": 20, "type": "private"}, "text": "status"}, "secret": "not used"}
    result = run(target.process_update(raw))
    assert result.success is True
    assert backend.questions == ["status"]
    assert "secret" not in repr(result)
