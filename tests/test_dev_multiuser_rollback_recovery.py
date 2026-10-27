from copy import deepcopy
from types import SimpleNamespace

import pytest

from scripts.dev_multiuser_rollback_recovery import _digest, verify_consumed_rollback
from scripts.dev_multiuser_test_users import _base, _token
from tests import test_dev_multiuser_confirmed_pair_recovery as pair_fixtures


ACCOUNT = "123456789012"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
AUTH = {"account": ACCOUNT, "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic", "source_sha": "b" * 40, "start": 2000}
SETUP = {"Resources": {"McpApi": {"Properties": {"DisableExecuteApiEndpoint": True}}}}
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
SUBJECT_A = "12345678-1234-7abc-1234-123456789abc"
SUBJECT_B = "22345678-1234-7abc-1234-123456789abc"
OLD_START, OLD_END = 100, 300
LATEST_START, LATEST_END = 1050, 1250
BINDING = {"schema": 1, "operation": "dev_multiuser_closed_update", "account": ACCOUNT,
           "caller": AUTH["expected_caller_arn"], "stack": STACK, "role": ROLE,
           "source": "a" * 40, "start": 1000, "end": 1300,
           "token": "dev-multiuser-" + "1" * 32, "prior": _digest(SETUP), "target": "c" * 64}


class Journal:
    def __init__(self, value):
        self.value = deepcopy(value)

    def load(self):
        return deepcopy(self.value)


class Cloud:
    def __init__(self):
        self.calls = []
        self.stack = {"StackId": STACK, "StackStatus": "UPDATE_ROLLBACK_COMPLETE", "RoleARN": ROLE, "EnableTerminationProtection": True}
        self.template = deepcopy(SETUP)
        self.events = [{"ClientRequestToken": BINDING["token"], "PhysicalResourceId": STACK,
                        "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "UPDATE_ROLLBACK_COMPLETE"}]
        self.next_token = None

    def describe_stacks(self, **kw):
        self.calls.append("stack")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Stacks": [self.stack]}

    def get_template(self, **kw):
        self.calls.append("template")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "TemplateBody": self.template}

    def describe_stack_events(self, **kw):
        self.calls.append("events")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackEvents": self.events, "NextToken": self.next_token}


def _user_states():
    original = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                     binding_sha256=_digest({"account_id": ACCOUNT, "user_pool_id": POOL,
                                             "run_id": RUN, "authorized_from_epoch": OLD_START,
                                             "authorized_until_epoch": OLD_END}),
                     start=OLD_START, end=OLD_END)
    original["preflight"] = True
    original["slots"][0].update({
        "create_status": "intent",
        "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")},
    })
    old_latest = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                       binding_sha256=_digest({"account_id": ACCOUNT, "user_pool_id": POOL,
                                               "run_id": RUN, "authorized_from_epoch": LATEST_START,
                                               "authorized_until_epoch": LATEST_END}),
                       start=LATEST_START, end=LATEST_END)
    old_latest["preflight"] = True
    old_latest["slots"][0].update({
        "create_status": "reconciled",
        "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")},
        "password_status": "confirmed",
        "password_intent": {"operation": "set-password", "token": _token(ACCOUNT, POOL, RUN, "A", "set-password")},
        "user_sub_sha256": _digest(SUBJECT_A),
    })
    original["slots"][1]["create_status"] = "pending"
    latest_pair = deepcopy(old_latest)
    latest_pair["slots"][1].update({
        "create_status": "created",
        "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "B", "create")},
        "password_status": "confirmed",
        "password_intent": {"operation": "set-password", "token": _token(ACCOUNT, POOL, RUN, "B", "set-password")},
        "user_sub_sha256": _digest(SUBJECT_B),
    })
    return original, old_latest, latest_pair


def _user_journals():
    original, _, latest_pair = _user_states()
    return Journal(original), Journal(latest_pair)


def _reset_state():
    original, old_latest, latest_pair = _user_states()
    context = {
        "account_id": ACCOUNT, "user_pool_id": POOL, "run_id": RUN,
        "source_sha256": BINDING["source"], "authorized_from_epoch": LATEST_START,
        "authorized_until_epoch": LATEST_END,
        "original_creation_sha256": _digest(original),
        # This is the historical A-only confirmation, not the later A+B pair.
        "latest_confirmed_sha256": _digest(old_latest),
        "original_start_epoch": OLD_START, "original_end_epoch": OLD_END,
        "confirmed_a_subject_sha256": _digest(SUBJECT_A), "reset_authorized": True,
    }
    binding = _digest(context)
    reset = {
        "schema": 1, "kind": "retained-dev-multiuser-confirmed-a-reset", "revision": 3,
        "phase": "complete", **context, "binding_sha256": binding,
        "reset_token": _digest({"operation": "reset-confirmed-a-password", "binding_sha256": binding}),
    }
    return Journal(original), Journal(latest_pair), reset


def check(cloud=None, state=None, reset=None):
    original, latest, canonical_reset = _reset_state()
    return verify_consumed_rollback(
        cloud or Cloud(),
        SimpleNamespace(load=lambda: state or {"binding": deepcopy(BINDING), "phase": "acknowledged"}),
        SimpleNamespace(load=lambda: reset or canonical_reset),
        auth=AUTH, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest, user_pool_id=POOL,
    )


def test_rollback_is_read_only_exact_and_bounded():
    cloud = Cloud()
    assert check(cloud)
    assert cloud.calls == ["stack", "template", "events"]


def test_prior_user_window_must_end_before_fresh_authority():
    original, latest, reset = _reset_state()
    cloud = Cloud()
    assert not verify_consumed_rollback(
        cloud, Journal({"binding": deepcopy(BINDING), "phase": "acknowledged"}), Journal(reset),
        auth=dict(AUTH, start=LATEST_END - 1), app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest, user_pool_id=POOL,
    )
    assert cloud.calls == []


def test_reset_window_must_match_confirmed_pair_and_stay_inside_outer_window():
    original, latest, reset = _reset_state()
    reset = deepcopy(reset)
    reset["authorized_from_epoch"], reset["authorized_until_epoch"] = BINDING["start"], BINDING["end"]
    context_keys = (
        "account_id", "user_pool_id", "run_id", "source_sha256", "authorized_from_epoch",
        "authorized_until_epoch", "original_creation_sha256", "latest_confirmed_sha256",
        "original_start_epoch", "original_end_epoch", "confirmed_a_subject_sha256", "reset_authorized",
    )
    context = {key: reset[key] for key in context_keys}
    reset["binding_sha256"] = _digest(context)
    reset["reset_token"] = _digest({"operation": "reset-confirmed-a-password",
                                     "binding_sha256": reset["binding_sha256"]})
    cloud = Cloud()
    result = verify_consumed_rollback(
        cloud, SimpleNamespace(load=lambda: {"binding": deepcopy(BINDING), "phase": "acknowledged"}),
        SimpleNamespace(load=lambda: reset), auth=AUTH, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest, user_pool_id=POOL,
    )
    assert result is False
    assert cloud.calls == []


@pytest.mark.parametrize("key,value", [("account", "999999999999"), ("caller", "foreign"), ("source", "b" * 40),
                                      ("start", True), ("prior", "d" * 64), ("token", "arbitrary"), ("role", "foreign")])
def test_wrong_binding_denied_without_network(key, value):
    state = {"binding": dict(BINDING, **{key: value}), "phase": "acknowledged"}
    cloud = Cloud()
    assert not check(cloud, state)
    assert not cloud.calls


@pytest.mark.parametrize("kind", ["pending", "template", "token", "duplicate", "pagination", "reset", "unacknowledged"])
def test_recovery_does_not_accept_ambiguous_or_foreign_history(kind):
    cloud = Cloud()
    reset = None
    state = None
    if kind == "pending": cloud.stack["StackStatus"] = "UPDATE_ROLLBACK_IN_PROGRESS"
    if kind == "template": cloud.template = {"Resources": {}}
    if kind == "token": cloud.events[0]["ClientRequestToken"] = "foreign"
    if kind == "duplicate": cloud.events *= 2
    if kind == "pagination": cloud.next_token = "more"
    if kind == "reset": reset = {"phase": "login_failed", "account_id": ACCOUNT, "source_sha256": "a" * 40}
    if kind == "unacknowledged": state = {"binding": BINDING, "phase": "intent"}
    assert not check(cloud, state, reset)


def _completed_pair_history():
    journals = pair_fixtures._initial_journals()
    original, first_pair, fresh, reset, provenance = journals
    cognito = pair_fixtures.Cognito()
    assert pair_fixtures._prepare(journals, cognito)["success"] is True
    assert pair_fixtures._execute(journals, cognito, on_user=lambda *_: None)["success"] is True
    return original, first_pair, fresh, reset


def test_recurring_pair_rollback_requires_and_accepts_exact_first_pair_chain():
    original, first_pair, latest_pair, reset = _completed_pair_history()
    binding = dict(BINDING, source=pair_fixtures.SOURCE,
                   start=pair_fixtures.NEW_START - 100, end=pair_fixtures.NEW_END + 100)
    auth = dict(AUTH, source_sha="e" * 40, start=pair_fixtures.NEW_END + 1000)
    cloud = Cloud()
    ok = verify_consumed_rollback(
        cloud, SimpleNamespace(load=lambda: {"binding": deepcopy(binding), "phase": "acknowledged"}),
        reset, auth=auth, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest_pair,
        first_confirmed_pair_journal=first_pair, recurring_pair=True, user_pool_id=POOL,
    )
    assert ok is True
    assert cloud.calls == ["stack", "template", "events"]

    forged = deepcopy(first_pair.load())
    forged["authorized_until_epoch"] += 100
    first_pair.state = forged
    rejected_cloud = Cloud()
    rejected = verify_consumed_rollback(
        rejected_cloud, SimpleNamespace(load=lambda: {"binding": deepcopy(binding), "phase": "acknowledged"}),
        reset, auth=auth, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest_pair,
        first_confirmed_pair_journal=first_pair, recurring_pair=True, user_pool_id=POOL,
    )
    assert rejected is False
    assert rejected_cloud.calls == []


def test_second_recurring_rollback_binds_f247_to_8ed_and_828c():
    original, first_pair, users_8ed, reset_8ed, prov_8ed = pair_fixtures._initial_journals()
    client = pair_fixtures.Cognito()
    first_journals = (original, first_pair, users_8ed, reset_8ed, prov_8ed)
    assert pair_fixtures._prepare(first_journals, client)["success"] is True
    assert pair_fixtures._execute(first_journals, client, on_user=lambda *_: None)["success"] is True
    history_8ed = pair_fixtures.validate_recurring_pair_history(
        original_creation_journal=original, first_confirmed_pair_journal=first_pair,
        latest_pair_journal=users_8ed, previous_reset_journal=reset_8ed,
        account=ACCOUNT, user_pool_id=POOL,
    )
    users_f247, reset_f247, prov_f247 = pair_fixtures.Journal(), pair_fixtures.Journal(), pair_fixtures.Journal()
    start, end = pair_fixtures.NEW_END + 100, pair_fixtures.NEW_END + 350
    assert pair_fixtures.prepare_confirmed_pair_reset(
        clients={"cognito": client}, original_creation_journal=original,
        latest_pair_journal=first_pair, fresh_user_journal=users_f247,
        reset_journal=reset_f247, provenance_journal=prov_f247,
        account=ACCOUNT, user_pool_id=POOL, source_sha256="d" * 40,
        authorized_from_epoch=start, authorized_until_epoch=end,
        allow_two_confirmed_user_resets=True,
        first_confirmed_pair_sha256=history_8ed["first_pair_sha256"],
        previous_reset_sha256=history_8ed["previous_reset_sha256"],
        wall_clock=lambda: start + 1,
    )["success"] is True
    assert pair_fixtures.reset_confirmed_pair_once(
        clients={"cognito": client}, fresh_user_journal=users_f247,
        reset_journal=reset_f247, account=ACCOUNT, user_pool_id=POOL,
        run_id=pair_fixtures.RUN, source_sha256="d" * 40,
        authorized_from_epoch=start, authorized_until_epoch=end,
        allow_two_confirmed_user_resets=True, on_confirmed_user=lambda *_: None,
        password_factory=lambda slot: pair_fixtures.PASSWORD_A if slot == "A" else pair_fixtures.PASSWORD_B,
        wall_clock=lambda: start + 1,
    )["success"] is True

    runtime_binding = dict(BINDING, source="d" * 40, start=start - 100, end=end + 100)
    auth = dict(AUTH, source_sha="e" * 40, start=end + 1000)
    cloud = Cloud()
    assert verify_consumed_rollback(
        cloud, SimpleNamespace(load=lambda: {"binding": runtime_binding, "phase": "acknowledged"}),
        reset_f247, auth=auth, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, first_confirmed_pair_journal=first_pair,
        latest_pair_journal=users_f247, earlier_reset_journal=reset_8ed,
        recurring_pair=True, user_pool_id=POOL,
    ) is True
    assert cloud.calls == ["stack", "template", "events"]

    forged_earlier = reset_8ed.load()
    forged_subject = "f" * 64
    forged_earlier["slots"][0]["subject_sha256"] = forged_subject
    forged_earlier["slots"][0]["reset_token"] = _digest({
        "operation": "reset-confirmed-pair-user",
        "binding_sha256": forged_earlier["binding_sha256"],
        "slot": "A", "subject_sha256": forged_subject,
    })
    reset_8ed.save(forged_earlier)
    forged_current = reset_f247.load()
    forged_current["previous_reset_sha256"] = _digest(forged_earlier)
    binding_fields = (
        "account_id", "user_pool_id", "run_id", "source_sha256",
        "authorized_from_epoch", "authorized_until_epoch", "original_creation_sha256",
        "latest_pair_sha256", "original_start_epoch", "original_end_epoch",
        "latest_start_epoch", "latest_end_epoch", "first_confirmed_pair_sha256",
        "previous_reset_sha256",
    )
    forged_base = {key: forged_current[key] for key in binding_fields}
    forged_current["binding_sha256"] = _digest(forged_base)
    for row in forged_current["slots"]:
        row["reset_token"] = _digest({
            "operation": "reset-confirmed-pair-user", "binding_sha256": forged_current["binding_sha256"],
            "slot": row["slot"], "subject_sha256": row["subject_sha256"],
        })
    reset_f247.save(forged_current)
    coherent_tamper = verify_consumed_rollback(
        Cloud(), SimpleNamespace(load=lambda: {"binding": runtime_binding, "phase": "acknowledged"}),
        reset_f247, auth=auth, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, first_confirmed_pair_journal=first_pair,
        latest_pair_journal=users_f247, earlier_reset_journal=reset_8ed,
        recurring_pair=True, user_pool_id=POOL,
    )
    assert coherent_tamper is False
