"""Independent synthetic SDK/post-enrollment composition; no network calls."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
import time
from types import SimpleNamespace

import pytest

from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from mapit.durable_tenants import DurableTenantGuard
from mapit.mapit_identity import MapitIdentityVerifier
from mapit.tenant_router import AuthenticatedTenant, InvitedTenantAuthority
from scripts import dev_owner_mapit_enrollment_readback as post
from scripts.dev_owner_enrolled_accepted_inputs import load_accepted_owner_delivery
from scripts.dev_owner_enrolled_observation import make_capsule, sha256_json
from scripts.dev_mapit_bootstrap_contract import build_plan
from scripts.run_dev_mapit_binding_key_setup import _verify_current_bootstrap_resources
from tests import test_dev_owner_enrolled_accepted_inputs as accepted_fixture
from tests.test_dev_owner_enrolled_delivery_sdk import _bundle_for


def _setup(tmp_path, monkeypatch):
    captured = {}
    original = accepted_fixture._private_inputs
    def capture(path):
        args, fixture = original(path)
        captured.update(fixture)
        return args, fixture
    monkeypatch.setattr(accepted_fixture, '_private_inputs', capture)
    root, paths, assembled, capsule = accepted_fixture._accepted(tmp_path)
    scenario = captured['scenario']
    scenario.phase = 'accepted'
    scenario.target = copy.deepcopy(assembled['target_template']) if 'target_template' in assembled else None
    # The actual owning loader reconstructs target; load once before synthetic
    # capsule baselines are replaced, then reload all parsers from final files.
    provisional = load_accepted_owner_delivery(delivery_root=root, private_paths=paths,
                                               acl_checker=lambda _: True)
    scenario.target = provisional.target_template
    scenario.delivery.coordinator.zip_sha = provisional.update_state['receipt']['artifact_sha256']
    authority = provisional.authority
    rows = scenario._rows(scenario.target, stack_id=authority['stack_id'],
                          stack_name='honda-mapit-mcp-dev-retained')
    historical = {}
    for index, key in enumerate(authority['historical_tenant_keys']):
        reply = scenario._dispatch('dynamodb', 'get_item', {'Key': {'key': {'S': key}}})
        historical['tenant_a' if index == 0 else 'tenant_b'] = sha256_json(reply['Item'])
    policy = scenario._dispatch('iam', 'get_role_policy', {
        'RoleName': post._ROLE, 'PolicyName': post._SYNTHETIC_POLICY})['PolicyDocument']
    update_path = root / 'update-intent/rehearsal-state.json'
    update = json.loads(update_path.read_bytes())
    capsule = make_capsule(delivery_binding=update['delivery_state']['binding'],
        progress={'resource_ids': {r['LogicalResourceId']: r['PhysicalResourceId'] for r in rows},
                  'historical_row_sha256': historical,
                  'authorization_table_id': '33333333-3333-4333-8333-333333333333',
                  'synthetic_policy_sha256': sha256_json(policy)},
        target_template_sha256=update['delivery_state']['receipt']['target_template_sha256'],
        artifact_sha256=update['delivery_state']['receipt']['artifact_sha256'],
        owner_context_sha256=update['delivery_state']['receipt']['owner_context_sha256'],
        accepted_read_call_count=150)
    update['delivery_state']['receipt']['runtime_evidence_sha256'] = capsule['runtime_evidence_sha256']
    accepted_fixture._write(root, 'observation-capsule.json', capsule)
    accepted_fixture._write(root, 'update-intent/rehearsal-state.json', update)
    evidence = load_accepted_owner_delivery(delivery_root=root, private_paths=paths,
                                            acl_checker=lambda _: True)
    manifest = parse_enrolled_dev_manifest(evidence.manifest_raw, evidence.invitation_jwks,
        evidence.mapit_jwks, expected_digest=evidence.authority['manifest_sha256'],
        account_id=evidence.authority['account_id'])
    invited = InvitedTenantAuthority(manifest.policies, manifest.invitation_keys, environment='dev')
    store = DynamoDBTenantStore(scenario.clients()['dynamodb'],
        table_arn=manifest.authorization_table_arn, allowed_keys=tuple(manifest.policies))
    guard = DurableTenantGuard(invited, store)
    now = int(time.time())
    owner = evidence.authority['owner_tenant_key']
    grant = AuthenticatedTenant(owner, now + 900, invited._proof(owner, now + 900))
    snapshot = guard.capture(grant)
    verifier = MapitIdentityVerifier(manifest.config, manifest.mapit_keys, b'v' * 32,
                                    clock=lambda: datetime.fromtimestamp(now, timezone.utc))
    calls = [0]
    def before():
        calls[0] += 1
        if calls[0] > 250:
            raise ValueError('synthetic-shared-budget')
    class Document:
        item = None
        meta = scenario.clients()['dynamodb'].meta
        def get_item(self, **kwargs):
            before()
            assert kwargs['Key'] == {'key': {'S': 'identity-bindings-v1'}}
            return {'ResponseMetadata': {'HTTPStatusCode': 200}, **(
                {'Item': copy.deepcopy(self.item)} if self.item else {})}
        def put_item(self, **kwargs):
            self.item = copy.deepcopy(kwargs['Item'])
            return {'ResponseMetadata': {'HTTPStatusCode': 200}}
    document = Document()
    registry_args = dict(table_arn=f"arn:aws:dynamodb:eu-west-1:{authority['account_id']}:table/{post._NAMESPACE}",
        account_id=authority['account_id'], authority=invited, durable_guard=guard,
        environment='dev', namespace='mapit', config=manifest.config, verifier=verifier,
        binding_key=b'b' * 32, auth_transport=lambda *_: {},
        clock=lambda: datetime.fromtimestamp(now, timezone.utc), monotonic=lambda: 100.0)
    registry = DynamoDBIdentityBindingRegistry(document, document, deadline=114,
        account_verifier=lambda *_: True, **registry_args)
    path = f'/honda-mapit-mcp/dev/tenants/{owner}/mapit-refresh-token'
    proof = verifier._proof('00000000-0000-4000-8000-000000000001')
    envelope = verifier.export_proof(proof, environment='dev', tenant_key=owner,
                                    secret_path=path, secret_version=1)
    tag = registry._identity_tag(proof)
    registry._write_document(0, {owner: registry._record(owner, None, path, 'pending', 1, None)})
    registry._write_document(1, {owner: registry._record(owner, tag, path, 'pending', 2, envelope)})
    registry._write_document(2, {owner: registry._record(owner, tag, path, 'active', 3, envelope)})
    binding = registry.get_binding(grant, snapshot)
    baseline_dispatch = scenario._dispatch
    mutation = [lambda service, method, kwargs, reply: reply]
    def dispatch(service, method, kwargs):
        if service == 'cloudformation' and kwargs.get('StackName', '').endswith(
                evidence.private_inputs.manifest_inputs['bootstrap_state']['readback_receipt']['stack_id'].rsplit('/', 1)[-1]):
            kwargs = dict(kwargs, StackName=post._NAMESPACE)
        if service == 'dynamodb' and method == 'get_item' and kwargs['Key']['key']['S'] == 'identity-bindings-v1':
            reply = document.get_item(**kwargs)
        elif service == 'ssm' and method == 'describe_parameters':
            publication = evidence.private_inputs.manifest_inputs['publication']
            name = kwargs['ParameterFilters'][0]['Values'][0]
            is_config = name == authority['mapit_config_path']
            session = f"mapit-key-{publication['run_id']}" if is_config else 'owner-mapit-' + 'a' * 32
            parameter = {
                'Name': name, 'Type': 'SecureString', 'DataType': 'text', 'Version': 1,
                'Tier': 'Standard', 'KeyId': 'alias/aws/ssm', 'Policies': [],
                'LastModifiedUser': f"arn:aws:sts::{authority['account_id']}:assumed-role/honda-mapit-mcp-dev-mapit-enroller/{session}",
                'LastModifiedDate': datetime.fromtimestamp(publication['start'] + 1 if is_config else now, timezone.utc)}
            reply = {'ResponseMetadata': {'HTTPStatusCode': 200},
                     'Parameters': [parameter] if name in {authority['mapit_config_path'], path} else []}
        elif service == 'ssm' and method == 'get_parameter':
            publication = evidence.private_inputs.manifest_inputs['publication']
            stamp = publication['start'] + 1 if kwargs['Name'] == authority['mapit_config_path'] else now
            reply = {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Parameter': {
                'Name': kwargs['Name'], 'ARN': f"arn:aws:ssm:eu-west-1:{authority['account_id']}:parameter{kwargs['Name']}",
                'Type': 'SecureString', 'DataType': 'text', 'Version': 1,
                'LastModifiedDate': datetime.fromtimestamp(stamp, timezone.utc)}}
        else:
            reply = baseline_dispatch(service, method, kwargs)
        return mutation[0](service, method, kwargs, copy.deepcopy(reply))
    scenario._dispatch = dispatch
    operation = 'a' * 32
    new_auth = {'kind': 'owner-mapit-enrollment-dev', 'schema': 1, 'operation_id': operation,
        'authorized_from_epoch': now - 1, 'authorized_until_epoch': now + 1000,
        'account_id': authority['account_id'], 'operator_arn': authority['operator_arn'],
        'owner_tenant_key': owner,
        'runtime_evidence_sha256': evidence.update_state['receipt']['runtime_evidence_sha256']}
    def readonly_factory(*, deadline):
        return DynamoDBIdentityBindingRegistry(document, None, deadline=deadline, **registry_args)
    kwargs = dict(operation_id=operation, grant=grant, snapshot=snapshot, binding=binding,
        registry=registry, authority=new_auth, client_bundle=_bundle_for(scenario.clients()),
        delivery_evidence=evidence, readonly_registry_factory=readonly_factory,
        before_sdk_call=before, deadline=200.0, clock=lambda: now, monotonic=lambda: 100.0)
    scenario.calls.clear()
    calls[0] = 0
    return SimpleNamespace(kwargs=kwargs, mutation=mutation, document=document, evidence=evidence,
                           scenario=scenario, calls=calls, registry=registry, owner=owner)


def test_actual_owning_loader_sdk_infrastructure_and_mac_restored_binding(tmp_path, monkeypatch):
    setup = _setup(tmp_path, monkeypatch)
    result = post.verify_owner_mapit_enrollment(**setup.kwargs)
    assert result['closed'] is True and result['reservation'] == 0
    assert result['secret_version'] == 1 and result['binding_revision'] == 3
    assert setup.evidence.assert_unchanged() is True
    assert '00000000-0000-4000-8000-000000000001' not in repr(result)


@pytest.mark.parametrize('drift', [
    'caller', 'template', 'api', 'reserve', 'namespace_role_id', 'namespace_boundary_id',
    'namespace_table_id', 'namespace_protection', 'namespace_schema', 'namespace_throughput',
    'namespace_stack_protection', 'enroller_boundary', 'kms', 'secret_version', 'secret_time',
])
def test_rejects_sdk_infrastructure_and_parameter_drift(tmp_path, monkeypatch, drift):
    setup = _setup(tmp_path, monkeypatch)
    def mutate(service, method, kwargs, reply):
        if drift == 'caller' and service == 'sts':
            reply['Arn'] = 'arn:aws:iam::123456789012:user/other'
        elif drift == 'template' and service == 'cloudformation' and method == 'get_template' and kwargs['StackName'] != post._NAMESPACE:
            reply['TemplateBody']['Description'] = 'unexpected'
        elif drift == 'api' and service == 'apigatewayv2' and method == 'get_api':
            reply['DisableExecuteApiEndpoint'] = False
        elif drift == 'reserve' and service == 'lambda' and method == 'get_function_concurrency':
            reply['ReservedConcurrentExecutions'] = 1
        elif drift.startswith('namespace_') and service == 'dynamodb' and method == 'describe_table' and kwargs['TableName'] == post._NAMESPACE:
            field = {'namespace_table_id': 'TableId', 'namespace_protection': 'DeletionProtectionEnabled',
                     'namespace_schema': 'KeySchema', 'namespace_throughput': 'OnDemandThroughput'}.get(drift)
            if field:
                reply['Table'][field] = {'namespace_table_id': 'wrong-id', 'namespace_protection': False,
                    'namespace_schema': [], 'namespace_throughput': {}}[drift]
        elif drift in {'namespace_role_id', 'namespace_boundary_id'} and service == 'cloudformation' and method == 'describe_stack_resources' and kwargs['StackName'] == post._NAMESPACE:
            logical = 'IdentityEnrollerRole' if drift == 'namespace_role_id' else 'IdentityEnrollerBoundary'
            next(r for r in reply['StackResources'] if r['LogicalResourceId'] == logical)['PhysicalResourceId'] = 'wrong-resource'
        elif drift == 'namespace_stack_protection' and service == 'cloudformation' and method == 'describe_stacks' and kwargs['StackName'] == post._NAMESPACE:
            reply['Stacks'][0]['EnableTerminationProtection'] = False
        elif drift == 'enroller_boundary' and service == 'iam' and method == 'get_role' and kwargs['RoleName'] != post._ROLE:
            reply['Role']['PermissionsBoundary']['PermissionsBoundaryArn'] = 'wrong-boundary'
        elif drift == 'kms' and service == 'kms':
            reply['KeyMetadata']['Enabled'] = False
        elif drift in {'secret_version', 'secret_time'} and service == 'ssm' and method == 'get_parameter':
            if drift == 'secret_version':
                reply['Parameter']['Version'] = 2
            else:
                reply['Parameter']['LastModifiedDate'] = datetime.fromtimestamp(1, timezone.utc)
        return reply
    setup.mutation[0] = mutate
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


@pytest.mark.parametrize('drift', ['extra', 'wrong_proof', 'bad_mac', 'doc_revision'])
def test_rejects_binding_identity_cardinality_and_mac_drift(tmp_path, monkeypatch, drift):
    setup = _setup(tmp_path, monkeypatch)
    if drift == 'wrong_proof':
        proof = setup.registry.verifier._proof('00000000-0000-4000-8000-000000000002')
        setup.kwargs['binding'] = replace(setup.kwargs['binding'], expected_identity_proof=proof)
    elif drift == 'bad_mac':
        setup.document.item['mac']['S'] = '0' * 64
    elif drift == 'doc_revision':
        _, records = setup.registry._read_document()
        setup.registry._write_document(3, records)
    else:
        _, records = setup.registry._read_document()
        extra = 'tenant-' + '9' * 64
        records[extra] = setup.registry._record(extra, None,
            f'/honda-mapit-mcp/dev/tenants/{extra}/mapit-refresh-token', 'pending', 1, None)
        setup.registry._write_document(2, records)
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


@pytest.mark.parametrize('drift', ['wall_expired', 'mono_expired', 'clock_nan', 'counter'])
def test_deadlines_and_shared_counter_fail_closed(tmp_path, monkeypatch, drift):
    setup = _setup(tmp_path, monkeypatch)
    if drift == 'wall_expired':
        setup.kwargs['clock'] = lambda: setup.kwargs['authority']['authorized_until_epoch']
    elif drift == 'mono_expired':
        samples = [100.0]
        setup.kwargs['monotonic'] = lambda: samples.pop(0) if samples else 200.0
    elif drift == 'clock_nan':
        setup.kwargs['clock'] = lambda: float('nan')
    else:
        setup.kwargs['before_sdk_call'] = lambda: (_ for _ in ()).throw(ValueError('PRIVATE-COUNTER-CANARY'))
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError) as caught:
        post.verify_owner_mapit_enrollment(**setup.kwargs)
    assert 'PRIVATE-COUNTER-CANARY' not in str(caught.value)


def test_latest_private_snapshot_drift_blocks_acceptance(tmp_path, monkeypatch):
    setup = _setup(tmp_path, monkeypatch)
    seen = [0]
    def drift(service, method, kwargs, reply):
        if service == 'sts':
            seen[0] += 1
            if seen[0] == 2:
                setup.evidence.target_template['Description'] = 'synthetic-private-drift'
        return reply
    setup.mutation[0] = drift
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


def test_provider_ciphertext_canary_is_not_in_acceptance_receipt(tmp_path, monkeypatch):
    setup = _setup(tmp_path, monkeypatch)
    def canary(service, method, kwargs, reply):
        if service == 'ssm' and method == 'get_parameter':
            assert kwargs['WithDecryption'] is False
            reply['Parameter']['Value'] = 'PRIVATE-CIPHERTEXT-CANARY'
        return reply
    setup.mutation[0] = canary
    result = post.verify_owner_mapit_enrollment(**setup.kwargs)
    assert 'PRIVATE-CIPHERTEXT-CANARY' not in json.dumps(result)


def test_historical_namespace_verifier_still_rejects_enrolled_document(tmp_path, monkeypatch):
    setup = _setup(tmp_path, monkeypatch)
    manifest = setup.evidence.private_inputs.manifest_inputs
    authority = manifest['bootstrap_authority']
    setup.scenario.calls.clear()
    with pytest.raises(ValueError):
        _verify_current_bootstrap_resources(setup.scenario.clients(), authority,
            manifest['bootstrap_state'], build_plan(authority),
            setup.evidence.authority['mapit_bootstrap_receipt_sha256'], [0], 100,
            200, lambda: 100)
    assert setup.scenario.calls[-1][0:2] == ('dynamodb', 'get_item')
    assert setup.scenario.calls[-1][2]['Key'] == {'key': {'S': 'identity-bindings-v1'}}


def test_binding_document_change_between_strong_reads_is_rejected(tmp_path, monkeypatch):
    setup = _setup(tmp_path, monkeypatch)
    reads = [0]
    def mutate(service, method, kwargs, reply):
        if service == 'dynamodb' and method == 'get_item' and kwargs['Key']['key']['S'] == 'identity-bindings-v1':
            reads[0] += 1
            if reads[0] == 2:
                reply['Item']['mac']['S'] = '0' * 64
        return reply
    setup.mutation[0] = mutate
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)
    assert reads[0] == 2


@pytest.mark.parametrize('drift', ['table', 'account', 'config', 'invited_subject'])
def test_registry_and_invitation_must_match_accepted_manifest(tmp_path, monkeypatch, drift):
    setup = _setup(tmp_path, monkeypatch)
    if drift == 'table':
        setup.registry._table_arn += '-wrong'
    elif drift == 'account':
        setup.registry._account_id = '999999999999'
    elif drift == 'config':
        from mapit.config import MapitConfig
        setup.registry._config = MapitConfig()
    else:
        invited = setup.registry._authority
        policy = invited._policies[setup.owner]
        invited._policies = {setup.owner: replace(policy,
            owner_subject='00000000-0000-4000-8000-000000000002')}
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


@pytest.mark.parametrize('which', ['mapit', 'invitation'])
def test_crossed_public_verification_material_is_rejected(tmp_path, monkeypatch, which):
    from cryptography.hazmat.primitives.asymmetric import rsa
    setup = _setup(tmp_path, monkeypatch)
    target = setup.registry.verifier if which == 'mapit' else setup.registry._authority._verifiers[setup.owner]
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    target._keys = {kid: replacement for kid in target._keys}
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


@pytest.mark.parametrize('field', ['Tier', 'KeyId', 'Policies', 'LastModifiedUser', 'NextToken'])
def test_parameter_inventory_metadata_is_exact(tmp_path, monkeypatch, field):
    setup = _setup(tmp_path, monkeypatch)
    def mutate(service, method, kwargs, reply):
        if service == 'ssm' and method == 'describe_parameters':
            if field == 'NextToken':
                reply[field] = 'unexpected-pagination'
            else:
                reply['Parameters'][0][field] = {'Tier': 'Advanced', 'KeyId': 'alias/wrong',
                    'Policies': [{'PolicyText': 'unexpected'}], 'LastModifiedUser': 'other-publisher'}[field]
        return reply
    setup.mutation[0] = mutate
    with pytest.raises(post.OwnerMapitEnrollmentReadbackError):
        post.verify_owner_mapit_enrollment(**setup.kwargs)


@pytest.mark.parametrize('case', ['absent', 'present', 'access_denied', 'wrong_http', 'bool_http', 'clock_expired', 'counter'])
def test_exact_session_absence_helper_counts_and_rejects_uncertainty(case):
    wall, mono, counter, requests = [1000.0], [10.0], [0], []
    class ProviderError(Exception):
        def __init__(self, code, status):
            self.response = {'Error': {'Code': code}, 'ResponseMetadata': {'HTTPStatusCode': status}}
            super().__init__('PRIVATE-ERROR-CANARY')
    class Ssm:
        def get_parameter(self, **kwargs):
            requests.append(kwargs)
            if case == 'present':
                return {'ResponseMetadata': {'HTTPStatusCode': 200}}
            if case == 'clock_expired':
                mono[0] = 20
            raise ProviderError('AccessDeniedException' if case == 'access_denied' else 'ParameterNotFound',
                                True if case == 'bool_http' else 404 if case == 'wrong_http' else 400)
    def before():
        counter[0] += 1
        if case == 'counter':
            raise ValueError
    budget = post._PostBudget(authority={}, observation_window={'authorized_from_epoch': 999,
        'authorized_until_epoch': 1100}, clock=lambda: wall[0], monotonic=lambda: mono[0],
        max_calls=2, deadline=20, before_sdk_call=before)
    budget.clients = {'ssm': Ssm()}
    path = '/honda-mapit-mcp/dev/tenants/tenant-' + 'b' * 64 + '/mapit-refresh-token'
    if case == 'absent':
        budget.confirm_session_absent(path)
    else:
        with pytest.raises(Exception) as caught:
            budget.confirm_session_absent(path)
        assert 'PRIVATE-ERROR-CANARY' not in str(caught.value)
    assert counter == [1]
    assert budget.calls == (0 if case == 'counter' else 1)
    assert requests == ([] if case == 'counter' else [{'Name': path, 'WithDecryption': False}])
