"""Independent operator boundaries, using only synthetic private fixtures."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from scripts import run_dev_owner_mapit_enrollment as runner
from scripts import dev_owner_mapit_private_baseline as baseline_module
from scripts.dev_owner_enrolled_accepted_inputs import load_accepted_owner_delivery
from tests.test_dev_owner_enrolled_accepted_inputs import _accepted
from tests.test_run_dev_owner_mapit_enrollment import NOW, SOURCE, authority, evidence, operation


@pytest.mark.parametrize('change', ['deadline', 'rollback', 'stale_gates'])
def test_private_scan_cost_cannot_dispatch_with_stale_clock_samples(tmp_path, change):
    mono = [100.0]
    op = operation(tmp_path, mono=lambda: mono[0])
    op.intent()
    def expensive_check():
        mono[0] = {'deadline': 114.0, 'rollback': 99.0, 'stale_gates': 130.0}[change]
        return True
    op.evidence.assert_unchanged = expensive_check
    calls = []
    client = SimpleNamespace(put_item=lambda **kwargs: calls.append(mono[0]) or {})
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        op.dispatch(client, 'put_item', {}, deadline=200 if change == 'stale_gates' else 114,
                    write='ddb')
    assert calls == []
    assert op.calls == op.ddb_writes == 0


def test_initial_clock_rollback_cannot_enter_before_authorized_start(tmp_path):
    root = tmp_path / 'fresh'
    root.mkdir()
    ev = evidence()
    (root / 'authorization.json').write_bytes(runner._canonical(authority(ev, state_directory=str(root.resolve()))))
    samples = [NOW]
    def wall():
        return samples.pop(0) if samples else NOW - 2
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._Operation(root=root, evidence=ev, source_sha=SOURCE, ci_run_id=999,
            acl_checker=lambda _: True, clock=wall, monotonic=lambda: 100)
    assert not (root / 'attempt.json').exists()


def _native_baseline(tmp_path):
    root, paths, _, _ = _accepted(tmp_path)
    ev = load_accepted_owner_delivery(delivery_root=root, private_paths=paths,
                                      acl_checker=lambda _: True)
    return root, ev, baseline_module.AcceptedPrivateBaseline(ev)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_native_baseline_cannot_remint_changed_historical_fingerprint(tmp_path):
    root, ev, baseline = _native_baseline(tmp_path)
    path = root / 'inputs/archive-summary.json'
    path.write_bytes(path.read_bytes() + b' ')
    assert baseline.check() is False and ev.assert_unchanged() is False
    maximum, _ = baseline.files[path]
    baseline.files[path] = (maximum, baseline_module._file_fingerprint(path, maximum))
    registrar = getattr(baseline, '_register', None)
    if registrar is not None:
        try:
            registrar()
        except baseline_module.PrivateBaselineError:
            pass
    assert baseline.check() is False
    assert baseline.is_registered_native() is False


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_forged_native_baseline_cannot_mint_registration(tmp_path):
    _, _, baseline = _native_baseline(tmp_path)
    forged = object.__new__(baseline_module.AcceptedPrivateBaseline)
    forged.__dict__.update(baseline.__dict__)
    registrar = getattr(forged, '_register', None)
    if registrar is not None:
        try:
            registrar()
        except baseline_module.PrivateBaselineError:
            pass
    assert forged.check() is False
    assert forged.is_registered_native() is False


def test_first_owner_cas_cannot_update_an_existing_namespace_document(tmp_path):
    op = operation(tmp_path)
    op.intent()
    calls = []
    raw = SimpleNamespace(meta=object(), put_item=lambda **kwargs: calls.append(kwargs) or {})
    table = 'arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-mapit-identity-bindings'
    client = runner._BoundClient(raw, op, deadline=114, table=table,
                                row_key='identity-bindings-v1', writable=True)
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        client.put_item(TableName=table, Item={'key': {'S': 'identity-bindings-v1'}, 'revision': {'N': '2'}},
            ConditionExpression='#revision = :revision', ExpressionAttributeNames={'#revision': 'revision'},
            ExpressionAttributeValues={':revision': {'N': '1'}}, ReturnValues='NONE')
    assert calls == [] and op.calls == op.ddb_writes == 0


@pytest.mark.parametrize('bad', ['item_revision', 'expected_revision'])
def test_later_owner_cas_revision_is_exact_before_dispatch(tmp_path, bad):
    op = operation(tmp_path)
    op.intent()
    op.ddb_writes = 1
    calls = []
    raw = SimpleNamespace(meta=object(), put_item=lambda **kwargs: calls.append(kwargs) or {})
    table = 'arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-mapit-identity-bindings'
    client = runner._BoundClient(raw, op, deadline=114, table=table,
                                row_key='identity-bindings-v1', writable=True)
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        client.put_item(TableName=table, Item={'key': {'S': 'identity-bindings-v1'},
            'revision': {'N': '3' if bad == 'item_revision' else '2'}},
            ConditionExpression='#revision = :revision', ExpressionAttributeNames={'#revision': 'revision'},
            ExpressionAttributeValues={':revision': {'N': '2' if bad == 'expected_revision' else '1'}},
            ReturnValues='NONE')
    assert calls == [] and op.calls == 0 and op.ddb_writes == 1


@pytest.mark.parametrize('format', ['legacy', 'v1'])
def test_readonly_session_uses_captured_native_backend_without_global_routing(format):
    from mapit.session import WindowsKeyringRefreshTokenStore
    import hashlib
    token = 'synthetic-native-refresh-session'
    values = {}
    native_calls = []
    def native_get(self, service, account):
        native_calls.append((service, account))
        return values.get((service, account))
    backend = type('WinVaultKeyring', (), {'__module__': 'keyring.backends.Windows',
                                          'get_password': native_get})()
    def forbidden_global(*args):
        raise AssertionError('readonly cannot route through mutable global backend')
    module = SimpleNamespace(get_password=forbidden_global, set_password=forbidden_global,
                             delete_password=forbidden_global, get_keyring=lambda: backend)
    store = WindowsKeyringRefreshTokenStore(keyring_module=module, backend=backend)
    if format == 'legacy':
        values[(store.SERVICE, store.ACCOUNT)] = token
    else:
        values[(store.SERVICE, store.MANIFEST_ACCOUNT)] = store._manifest_text(1, hashlib.sha256(token.encode()).hexdigest())
        values[(store.SERVICE, store._chunk_account(0))] = token
        values[(store.SERVICE, store.ACCOUNT)] = 'synthetic-legacy-must-remain'
    before = dict(values)
    assert store.load_readonly() == token
    assert values == before and native_calls


@pytest.mark.parametrize('consent,elapsed', [(False, 0), (True, 10)])
def test_consent_rejection_or_dialog_expiry_prevents_any_saved_session_read(consent, elapsed):
    mono = [100.0]
    def ask():
        mono[0] += elapsed
        return consent
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._collect_saved_session(consent_request=ask, deadline=110,
            monotonic=lambda: mono[0], store_factory=lambda: pytest.fail('no store before live consent'))


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_genuine_full_runner_with_real_clocks_and_bounded_sdk_latency(tmp_path, monkeypatch):
    pytest.importorskip('boto3')
    import time
    from tests.test_run_dev_owner_mapit_enrollment import test_actual_private_preflight_to_sdk_shaped_enrollment_and_closed_post
    actual = runner._Operation.dispatch
    latency = [0]
    def delayed(self, *args, **kwargs):
        time.sleep(0.06)
        latency[0] += 1
        return actual(self, *args, **kwargs)
    monkeypatch.setattr(runner._Operation, 'dispatch', delayed)
    # This shared owning scenario executes real JWT verification, native
    # provenance, actual registry CAS/MAC and the independent closed observer.
    # All SDK/HTTP wire edges are modeled, with network explicitly forbidden.
    test_actual_private_preflight_to_sdk_shaped_enrollment_and_closed_post(
        tmp_path, monkeypatch, 'real_monotonic')
    assert latency[0] >= 20


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_genuine_full_runner_excessive_real_latency_is_consumed_and_held(tmp_path, monkeypatch):
    pytest.importorskip('boto3')
    import time
    from tests.test_run_dev_owner_mapit_enrollment import test_actual_private_preflight_to_sdk_shaped_enrollment_and_closed_post
    actual_dispatch = runner._Operation.dispatch
    actual_runner = runner.run_owner_mapit_enrollment
    results = []
    def delayed(self, *args, **kwargs):
        if self._intent:
            time.sleep(0.7)
        return actual_dispatch(self, *args, **kwargs)
    def capture(**kwargs):
        result = actual_runner(**kwargs)
        results.append(result)
        return result
    monkeypatch.setattr(runner._Operation, 'dispatch', delayed)
    monkeypatch.setattr(runner, 'run_owner_mapit_enrollment', capture)
    # The shared positive scenario asserts success. Catch that assertion only
    # after the real runner reports a held excessive-latency outcome.
    with pytest.raises(AssertionError):
        test_actual_private_preflight_to_sdk_shaped_enrollment_and_closed_post(
            tmp_path, monkeypatch, 'real_monotonic')
    assert len(results) == 1 and results[0]['ok'] is False
    assert results[0]['category'] == 'owner_mapit_enrollment_unverified'
    assert 1 <= results[0]['ddb_writes'] <= 3 and results[0]['ssm_writes'] <= 1
    root = tmp_path / 'fresh-operation'
    assert (root / 'attempt.json').exists() and (root / 'intent.json').exists()
    assert not (root / 'result.json').exists()


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_native_admission_must_bind_the_authorization_snapshot_it_validated(tmp_path, monkeypatch):
    import json
    _, ev, baseline = _native_baseline(tmp_path / 'history')
    root = tmp_path / 'fresh'
    root.mkdir()
    path = root / 'authorization.json'
    path.write_bytes(runner._canonical(authority(ev, state_directory=str(root.resolve()))))
    original_add = baseline.add
    def racing_add(target, **kwargs):
        if Path(target).name == 'authorization.json':
            value = json.loads(Path(target).read_bytes())
            value['max_sdk_calls'] = 1
            Path(target).write_bytes(runner._canonical(value))
        return original_add(target, **kwargs)
    monkeypatch.setattr(baseline, 'add', racing_add)
    with pytest.raises(Exception):
        runner._Operation(root=root, evidence=ev, source_sha=SOURCE, ci_run_id=999,
            acl_checker=lambda _: True, clock=lambda: NOW, monotonic=lambda: 100,
            private_baseline=baseline)
    assert not (root / 'attempt.json').exists()


@pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptor')
def test_native_new_fence_must_bind_exact_persisted_snapshot(tmp_path, monkeypatch):
    import json
    _, ev, baseline = _native_baseline(tmp_path / 'history')
    root = tmp_path / 'fresh'
    root.mkdir()
    (root / 'authorization.json').write_bytes(runner._canonical(authority(ev, state_directory=str(root.resolve()))))
    op = runner._Operation(root=root, evidence=ev, source_sha=SOURCE, ci_run_id=999,
        acl_checker=lambda _: True, clock=lambda: NOW, monotonic=lambda: 100,
        private_baseline=baseline)
    op.gates_verified()
    original_add = baseline.add
    def racing_add(target, **kwargs):
        if Path(target).name == 'intent.json':
            value = json.loads(Path(target).read_bytes())
            value['ddb_cas_limit'] = 1
            Path(target).write_bytes(runner._canonical(value))
        return original_add(target, **kwargs)
    monkeypatch.setattr(baseline, 'add', racing_add)
    with pytest.raises(Exception):
        op.intent()
    assert not op._intent and op.ddb_writes == op.ssm_writes == 0
    assert (root / 'intent.json').exists()
