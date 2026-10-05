import json
from types import SimpleNamespace

import pytest

from mapit.telegram_credentials import TelegramCredentialStoreError, WindowsKeyringTelegramCredentialStore


TOKEN = "123456789:ABCDEFGHIJKLMNOPQRST"
TOKEN_B = "987654321:ZYXWVUTSRQPONMLKJIHG"


class FakeKeyring:
    def __init__(self):
        self.values = {}
        self.errors = SimpleNamespace(PasswordDeleteError=type("PasswordDeleteError", (Exception,), {}))
        self.fail_set = False

    def set_password(self, service, account, value):
        if self.fail_set:
            raise OSError("private")
        self.values[(service, account)] = value

    def get_password(self, service, account):
        return self.values.get((service, account))

    def delete_password(self, service, account):
        key = (service, account)
        if key not in self.values:
            raise self.errors.PasswordDeleteError()
        del self.values[key]


def _backend():
    return type("WinVaultKeyring", (), {"__module__": "keyring.backends.Windows"})()


def _store():
    fake = FakeKeyring()
    return fake, WindowsKeyringTelegramCredentialStore(keyring_module=fake, backend=_backend())


def test_store_uses_one_canonical_state_entry_and_projects_values():
    fake, store = _store()
    challenge = "A" * 43
    store.save_token(TOKEN, challenge=challenge)
    assert store.load_token() == TOKEN
    assert store.load_challenge() == challenge
    with pytest.raises(TelegramCredentialStoreError):
        store.load()
    store.save_allowlist((10, 20))
    with pytest.raises(TelegramCredentialStoreError):
        store.load()
    assert set(fake.values) == {(store.SERVICE, store.STATE_ACCOUNT)}
    envelope = json.loads(fake.values[(store.SERVICE, store.STATE_ACCOUNT)])
    assert envelope == {
        "format": "telegram-state-v1",
        "version": 1,
        "token": TOKEN,
        "pairs": [[10, 20]],
        "challenge": challenge,
    }
    store.delete_challenge(challenge)
    assert store.load_challenge() is None
    loaded = store.load()
    assert loaded is not None and loaded.token == TOKEN and loaded.allowed_pairs == frozenset({(10, 20)})
    assert TOKEN.split(":", 1)[1] not in repr(loaded)
    store.delete()
    store.delete()
    assert store.load() is None


def test_store_rejects_wrong_backend_partial_or_noncanonical_state():
    fake = FakeKeyring()
    with pytest.raises(TelegramCredentialStoreError):
        WindowsKeyringTelegramCredentialStore(keyring_module=fake, backend=object())
    store = WindowsKeyringTelegramCredentialStore(keyring_module=fake, backend=_backend())
    key = (store.SERVICE, store.STATE_ACCOUNT)
    fake.values[key] = TOKEN
    with pytest.raises(TelegramCredentialStoreError):
        store.load_token()
    fake.values[key] = json.dumps({"format": "telegram-state-v1", "version": 1, "token": TOKEN, "pairs": None, "challenge": None})
    with pytest.raises(TelegramCredentialStoreError):
        store.load_token()
    fake.values[key] = json.dumps({"format": "telegram-state-v1", "version": 1, "token": TOKEN, "pairs": None, "challenge": None}, separators=(",", ":"), sort_keys=True) + " "
    with pytest.raises(TelegramCredentialStoreError):
        store.load_token()


def test_failed_single_write_preserves_previous_rotation_state():
    fake, store = _store()
    store.save(TOKEN, ((10, 20),))
    key = (store.SERVICE, store.STATE_ACCOUNT)
    previous = fake.values[key]
    fake.fail_set = True
    with pytest.raises(TelegramCredentialStoreError):
        store.save_token(TOKEN_B, challenge="B" * 43)
    assert fake.values[key] == previous
    fake.fail_set = False
    assert store.load().token == TOKEN
    assert store.load().allowed_pairs == frozenset({(10, 20)})


def test_token_only_state_clears_pairs_and_requires_pair_for_runtime():
    fake, store = _store()
    store.save_token(TOKEN, challenge="A" * 43)
    with pytest.raises(TelegramCredentialStoreError):
        store.load()
    store.save_allowlist((10, 20))
    store.save_token(TOKEN_B, challenge="B" * 43)
    assert store.load_token() == TOKEN_B
    with pytest.raises(TelegramCredentialStoreError):
        store.load()
    assert store.load_challenge() == "B" * 43


def test_challenge_delete_preserves_token_and_allowlist():
    _, store = _store()
    store.save_token(TOKEN, challenge="A" * 43)
    store.save_allowlist((10, 20))
    challenge = store.load_challenge()
    assert challenge
    with pytest.raises(TelegramCredentialStoreError):
        store.load()
    store.delete_challenge(challenge)
    loaded = store.load()
    assert loaded is not None and loaded.allowed_pairs == frozenset({(10, 20)})
    with pytest.raises(TelegramCredentialStoreError):
        store.delete_challenge(challenge)


@pytest.mark.parametrize("token", ["secret", "123:short", "abc:ABCDEFGHIJKLMNOPQRST", "123456789:ABCDEFGHIJKLMNOPQRST!"])
def test_token_format_is_conservative(token):
    _, store = _store()
    with pytest.raises(TelegramCredentialStoreError):
        store.save_token(token)


def test_pairs_and_state_size_are_bounded():
    _, store = _store()
    with pytest.raises(TelegramCredentialStoreError):
        store.save(TOKEN, tuple((n + 1, n + 2) for n in range(store.MAX_PAIRS + 1)))


def test_complete_save_has_no_pending_challenge():
    _, store = _store()
    assert store.save(TOKEN, ((10, 20),)) is None
    assert store.load_challenge() is None
    assert store.load() is not None


@pytest.mark.parametrize(
    "envelope",
    [
        {"format": "telegram-state-v1", "version": 1, "token": None, "pairs": [[10, 20]], "challenge": None},
        {"format": "telegram-state-v1", "version": 1, "token": None, "pairs": None, "challenge": "A" * 43},
    ],
)
def test_state_invariants_reject_pairs_or_challenge_without_token(envelope):
    fake, store = _store()
    fake.values[(store.SERVICE, store.STATE_ACCOUNT)] = json.dumps(
        envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    with pytest.raises(TelegramCredentialStoreError):
        store.load_token()
