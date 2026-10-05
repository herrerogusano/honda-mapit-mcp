"""Execute the credential-free inline gate, not a duplicated approximation."""
import copy
import json
import subprocess
import time
from types import SimpleNamespace

import pytest

from test_run_cd_release import _source_gate_documents, _source_gate_script


def execute(monkeypatch, tmp_path, *, pending_reads=0, mutate=None):
    sha, repo, run_id, documents = _source_gate_documents()
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"workflow_run": {"id": run_id, "head_sha": sha},
                                "repository": {"id": 7654321, "owner": {"id": 1234567}}}))
    output = tmp_path / "outputs"
    for key, value in {"EVENT_PATH": str(event), "REPOSITORY": repo,
                       "REPOSITORY_ID": "7654321", "REPOSITORY_OWNER_ID": "1234567",
                       "WORKFLOW_RUN_ID": str(run_id), "DEFAULT_SHA": sha,
                       "GITHUB_OUTPUT": str(output)}.items():
        monkeypatch.setenv(key, value)
    reads, sleeps = [], []

    def api(args, **kwargs):
        payload = copy.deepcopy(documents[args[-1]])
        if "/check-runs?" in args[-1]:
            reads.append(True)
            if len(reads) <= pending_reads:
                payload["check_runs"][0].update(status="in_progress", conclusion=None)
            if mutate:
                mutate(payload)
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

    monkeypatch.setattr(subprocess, "run", api)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    return lambda: exec(compile(_source_gate_script(), "source-gate", "exec"), {}), reads, sleeps, output


def test_same_source_pending_check_may_finish_within_fixed_bound(monkeypatch, tmp_path):
    run, reads, sleeps, output = execute(monkeypatch, tmp_path, pending_reads=1)
    run()
    assert len(reads) == 2 and sleeps == [2]
    assert output.read_text() == "source_sha=" + "a" * 40 + "\n"


def test_pending_checks_do_not_extend_bound_or_emit_values(monkeypatch, tmp_path, capsys):
    run, reads, sleeps, output = execute(monkeypatch, tmp_path, pending_reads=10)
    with pytest.raises(SystemExit):
        run()
    assert len(reads) == 5 and sleeps == [2] * 4 and not output.exists()
    diagnostics = capsys.readouterr().out
    assert '"stage": "required_checks"' in diagnostics
    assert "a" * 40 not in diagnostics and "7654321" not in diagnostics


@pytest.mark.parametrize("mutate", [
    lambda x: x["check_runs"][0].update(status="completed", conclusion="failure"),
    lambda x: x["check_runs"][0].update(head_sha="b" * 40),
    lambda x: x["check_runs"][0].update(app={"id": 99999}),
    lambda x: x.update(total_count=101),
])
def test_negative_or_truncated_check_response_is_never_polled(monkeypatch, tmp_path, mutate):
    run, reads, sleeps, output = execute(monkeypatch, tmp_path, mutate=mutate)
    with pytest.raises(SystemExit):
        run()
    assert len(reads) == 1 and not sleeps and not output.exists()
