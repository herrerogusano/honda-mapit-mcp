from __future__ import annotations

import pytest

from scripts.dev_multiuser_test_users import DevMultiuserTestUserOperator
from scripts.run_aws_closed_rehearsal import MemoryJournal


ACCOUNT = "123456789012"
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
START = 1_800_000_000


class _NotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "UserNotFoundException"}}


class _ClockedCognito:
    def __init__(self):
        self.operator = None
        self.calls = 0

    def admin_get_user(self, **_kwargs):
        self.calls += 1
        if self.calls == 2:
            # Expire during the final provider read.  The operator must not
            # commit a successful preflight after that read.
            self.operator.wall_clock()
        raise _NotFound()


def test_preflight_rechecks_deadline_before_committing_after_provider_reads():
    ticks = iter((START + 1, START + 1, START + 301))
    clock = lambda: next(ticks)
    journal = MemoryJournal()
    client = _ClockedCognito()
    operator = DevMultiuserTestUserOperator(
        {"cognito": client}, journal,
        account_id=ACCOUNT, user_pool_id=POOL, run_id=RUN,
        authorized_from_epoch=START, authorized_until_epoch=START + 300,
        wall_clock=clock,
    )
    client.operator = operator

    result = operator.preflight()

    assert result["category"] == "window_expired"
    assert journal.value is None
