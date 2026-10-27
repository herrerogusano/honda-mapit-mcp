import pytest
from tests.test_github_dev_source_gate import _documents, _run, RUN_ID


def test_each_job_must_bind_source_explicitly():
    documents = _documents()
    documents[f"actions/runs/{RUN_ID}/jobs"]["jobs"][0].pop("head_sha")
    assert _run(documents)["category"] == "ci_jobs_mismatch"


@pytest.mark.parametrize("target", ["repository", "owner", "run", "workflow"])
def test_response_ids_must_be_actual_integers(target):
    documents = _documents()
    row = {"repository": documents["repository"], "owner": documents["repository"]["owner"],
           "run": documents[f"actions/runs/{RUN_ID}"], "workflow": documents["actions/workflows/9911"]}[target]
    row["id"] = float(row["id"])
    assert _run(documents)["ok"] is False
