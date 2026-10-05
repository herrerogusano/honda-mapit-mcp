import copy

import pytest

from scripts.build_aws_prod_artifacts import fixed_prod_artifact_template


def test_retention_changes_only_journal_lifecycle_and_preserves_legacy():
    legacy = fixed_prod_artifact_template()
    updated = fixed_prod_artifact_template(journal_retention_days=30)
    restored = copy.deepcopy(updated)
    buckets = [v for v in restored['Resources'].values() if v['Type'] == 'AWS::S3::Bucket']
    assert len(buckets) == 1
    assert buckets[0]['Properties'].pop('LifecycleConfiguration') == {'Rules': [{
        'Id': 'CdDeliveryJournalRetention', 'Status': 'Enabled',
        'Prefix': 'journals/', 'TagFilters': [{'Key': 'cd-terminal', 'Value': 'true'}],
        'ExpirationInDays': 30,
    }]}
    assert restored == legacy
    assert fixed_prod_artifact_template() == legacy


@pytest.mark.parametrize('days', [True, False, 0, 1, 29, 31, 30.0, '30'])
def test_retention_rejects_other_values(days):
    with pytest.raises(ValueError, match='journal_retention_invalid'):
        fixed_prod_artifact_template(journal_retention_days=days)
