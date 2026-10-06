import pytest

from scripts.aws_retained_dev_journal import RetainedDevJournalError, RetainedDevS3Journal
from tests.test_aws_retained_dev_journal import ACCOUNT, RUN, SOURCE, S3


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_remote_state_rejected_before_injected_validator(constant):
    client = S3()
    reached = []
    journal = RetainedDevS3Journal(client, account_id=ACCOUNT, source_sha=SOURCE,
                                  run_id=RUN, phase="artifact",
                                  state_validator=lambda state: reached.append(state) or True)
    raw = ('{"schema":1,"kind":"retained-dev-journal","account_id":"' + ACCOUNT
           + '","source_sha":"' + SOURCE + '","run_id":"' + RUN
           + '","phase":"artifact","revision":1,"previous_sha256":null,'
             '"state":{"value":' + constant + '}}').encode("ascii")
    client.objects[journal.key] = (raw, '"etag1"')
    with journal.locked(), pytest.raises(RetainedDevJournalError, match="journal_invalid"):
        journal.load()
    assert reached == []
