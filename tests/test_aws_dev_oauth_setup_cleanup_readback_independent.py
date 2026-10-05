from __future__ import annotations

from scripts.aws_dev_oauth_setup_cleanup_readback import check_oauth_setup_cleanup
from test_aws_dev_oauth_setup_cleanup_readback import ACCOUNT, Cfn, Cognito, _ok, _state


def test_any_nonempty_domain_description_is_not_proof_of_absence():
    class ResidualDomain(Cognito):
        def describe_user_pool_domain(self, *, Domain):
            return _ok(DomainDescription={"CloudFrontDistribution": "distribution-canary"})

    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": ResidualDomain()}, state=_state(), expected_account_id=ACCOUNT,
    )

    assert result.verified is False
    assert result.category == "domain_still_present"
    assert result.domain_absent is False
    assert "distribution-canary" not in repr(result.safe_projection())


def test_malformed_cloudformation_status_stops_before_cognito_queries():
    class Non200(Cfn):
        def describe_stacks(self, *, StackName):
            return {"Stacks": [], "ResponseMetadata": {"HTTPStatusCode": 202}}

    class MustNotCall(Cognito):
        def describe_user_pool(self, *, UserPoolId):
            raise AssertionError("must stop after malformed first read")

    result = check_oauth_setup_cleanup(
        {"cloudformation": Non200(), "cognito": MustNotCall()}, state=_state(), expected_account_id=ACCOUNT,
    )

    assert result.verified is False
    assert result.category == "cleanup_readback_failed"
    assert result.calls == 1
