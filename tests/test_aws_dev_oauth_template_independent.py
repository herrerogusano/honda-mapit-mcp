from __future__ import annotations

import copy

import pytest

from scripts import build_aws_dev_oauth_template as composer
from scripts.build_aws_dev_bootstrap import _read_scaffold
from tests.test_aws_dev_oauth_template import _build


@pytest.mark.parametrize(("logical_id", "extra_property", "value"), [
    (
        "McpUserPoolDomain",
        "CustomDomainConfig",
        {"CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/synthetic"},
    ),
    (
        "McpUserPoolClient",
        "AnalyticsConfiguration",
        {
            "ApplicationArn": "arn:aws:mobiletargeting:eu-west-1:123456789012:apps/synthetic",
            "RoleArn": "arn:aws:iam::123456789012:role/synthetic-external-analytics",
            "UserDataShared": True,
        },
    ),
])
def test_composer_rejects_unreviewed_external_resource_properties(
    monkeypatch: pytest.MonkeyPatch,
    logical_id: str,
    extra_property: str,
    value: dict,
):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"][logical_id]["Properties"][extra_property] = value
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)

    with pytest.raises(composer.OAuthTemplateError):
        _build()
