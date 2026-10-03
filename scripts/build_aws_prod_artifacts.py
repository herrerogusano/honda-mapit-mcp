"""Compose a private retained production artifact bucket offline only."""
from scripts.build_aws_dev_runtime_template import fixed_runtime_bucket_template


def fixed_prod_artifact_template():
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
    return template
