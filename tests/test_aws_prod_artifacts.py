from scripts.build_aws_prod_artifacts import fixed_prod_artifact_template


def test_private_retained_prod_bucket_only():
    template = fixed_prod_artifact_template()
    assert len(template['Resources']) == 2
    assert template['Conditions']['SupportedDeployment']['Fn::And'] == [
        {'Fn::Equals': [{'Ref': 'AWS::Region'}, 'eu-west-1']},
        {'Fn::Equals': [{'Ref': 'AWS::StackName'}, 'honda-mapit-mcp-prod-runtime-artifacts']},
    ]
    for resource in template['Resources'].values():
        assert resource['DeletionPolicy'] == resource['UpdateReplacePolicy'] == 'Retain'
    bucket = template['Resources']['RuntimeArtifactBucket']['Properties']
    assert all(bucket['PublicAccessBlockConfiguration'].values())
    assert bucket['OwnershipControls']['Rules'] == [{'ObjectOwnership': 'BucketOwnerEnforced'}]
    assert bucket['BucketEncryption']['ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256'
    assert {'Key': 'Environment', 'Value': 'prod'} in bucket['Tags']
    assert 'BucketName' not in bucket and 'VersioningConfiguration' not in bucket
    assert template == fixed_prod_artifact_template()
