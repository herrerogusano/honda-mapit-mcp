"""Compose a private retained production artifact bucket offline only."""
from scripts.build_aws_dev_runtime_template import fixed_runtime_bucket_template


def fixed_prod_artifact_template(*, journal_retention_days=None):
    if journal_retention_days is not None and (type(journal_retention_days) is not int or journal_retention_days != 30):
        raise ValueError('journal_retention_invalid')
    template = fixed_runtime_bucket_template()
    template['Description'] = 'Private retained production code artifacts; no credentials or history.'
    template['Metadata'] = {'Environment': 'prod', 'NoDeployment': True,
                            'ContainsOnlyCodeAndPublicBindings': True}
    template['Conditions']['SupportedDeployment']['Fn::And'][1]['Fn::Equals'][1] = 'honda-mapit-mcp-prod-runtime-artifacts'
    for resource in template['Resources'].values():
        resource['DeletionPolicy'] = 'Retain'
        resource['UpdateReplacePolicy'] = 'Retain'
        for tag in resource.get('Properties', {}).get('Tags', []):
            if tag['Key'] == 'Environment': tag['Value'] = 'prod'
            if tag['Key'] == 'Purpose': tag['Value'] = 'production-runtime-artifact'
        if resource['Type'] == 'AWS::S3::Bucket' and journal_retention_days is not None:
            resource['Properties']['LifecycleConfiguration'] = {'Rules': [{
                'Id': 'CdDeliveryJournalRetention', 'Status': 'Enabled',
                'Prefix': 'journals/', 'TagFilters': [{'Key': 'cd-terminal', 'Value': 'true'}],
                'ExpirationInDays': journal_retention_days,
            }]}
    return template
