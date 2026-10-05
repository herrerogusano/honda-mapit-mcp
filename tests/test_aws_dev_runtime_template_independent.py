from __future__ import annotations

import pytest

from scripts.build_aws_dev_runtime_template import (
    RuntimeTemplateError,
    fixed_runtime_candidate_template,
)


@pytest.mark.parametrize("bucket_name", [
    "xn--reserved-name",
    "sthree-reserved-name",
    "amzn-s3-demo-reserved-name",
    "honda-dev-s3alias",
    "honda-dev-ext-s3alias",
    "honda-dev--ol-s3",
    "honda-dev.mrap",
    "honda-dev--x-s3",
    "honda-dev--table-s3",
])
def test_candidate_rejects_s3_reserved_bucket_prefixes_and_suffixes(bucket_name):
    with pytest.raises(RuntimeTemplateError, match="runtime_bucket_name_invalid"):
        fixed_runtime_candidate_template(bucket_name, "a" * 64)
