from scripts.telegram_setup_gui import load_telegram_challenge


class ChallengeStore:
    def __init__(self, challenge=None, error=None):
        self.challenge = challenge
        self.error = error

    def load_challenge(self):
        if self.error is not None:
            raise self.error
        return self.challenge


def test_setup_helper_loads_existing_challenge_without_gui_or_output(capsys):
    challenge = "A" * 43
    result = load_telegram_challenge(ChallengeStore(challenge))
    assert result == {"success": True, "category": "challenge_available", "challenge": challenge}
    assert capsys.readouterr().out == ""


def test_setup_helper_reports_empty_challenge_safely():
    assert load_telegram_challenge(ChallengeStore()) == {"success": True, "category": "no_challenge"}


def test_setup_helper_redacts_store_failure():
    assert load_telegram_challenge(ChallengeStore(error=RuntimeError("secret"))) == {
        "success": False,
        "category": "credential_store_failed",
    }
