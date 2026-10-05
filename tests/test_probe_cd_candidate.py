import hashlib
import json

import pytest

from scripts import probe_cd_candidate as probe


def test_exact_candidate_uses_offline_pinned_arm_and_closed_output(tmp_path, monkeypatch):
    archive = tmp_path / 'runtime.zip'
    archive.write_bytes(b'synthetic-zip')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    calls = []
    monkeypatch.setattr(probe.docker_helpers, '_docker_context', lambda: 'default')
    monkeypatch.setattr(probe.docker_helpers, '_cleanup_owned_container', lambda *args: True)
    def process(command, payload, *, timeout):
        calls.append(command)
        assert json.loads(payload) == {'zip_sha256': digest, 'manifest_sha256': 'b'*64, 'source_sha': 'c'*40}
        assert timeout == 240
        return 0, json.dumps({'checks': {key: True for key in probe.CHECKS}})
    monkeypatch.setattr(probe, '_run_bounded_process', process)
    assert probe.probe_candidate(archive, zip_sha256=digest, manifest_sha256='b'*64, source_sha='c'*40)
    assert '--network' in calls[0] and calls[0][calls[0].index('--network')+1] == 'none'
    assert '--platform' in calls[0] and calls[0][calls[0].index('--platform')+1] == 'linux/arm64'
    assert '--env' not in calls[0] and '-e' not in calls[0]
    assert probe.IMAGE in calls[0] and '@sha256:' in probe.IMAGE


@pytest.mark.parametrize('digest', ['x'*64, 'a'*63, True])
def test_invalid_candidate_never_constructs_docker(tmp_path, monkeypatch, digest):
    monkeypatch.setattr(probe.docker_helpers, '_docker_context', lambda: pytest.fail('docker reached'))
    assert not probe.probe_candidate(tmp_path/'absent', zip_sha256=digest, manifest_sha256='b'*64, source_sha=None)
