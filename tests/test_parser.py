"""Unit tests for prowler.parsers.prowler."""

import json
import tempfile
from pathlib import Path
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from prowler.parsers import prowler as parser


SAMPLE_FINDINGS = [
    {
        "Provider": "aws",
        "CheckID": "iam_root_mfa_enabled",
        "CheckTitle": "Ensure MFA is enabled for root",
        "ServiceName": "iam",
        "Status": "FAIL",
        "StatusExtended": "MFA is not enabled.",
        "Severity": "critical",
        "ResourceId": "arn:aws:iam::123456789012:root",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Timestamp": "2026-05-07T08:00:00.000000",
        "FindingUniqueId": "prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1",
    },
    {
        "Provider": "aws",
        "CheckID": "s3_bucket_public_access",
        "CheckTitle": "S3 public access check",
        "ServiceName": "s3",
        "Status": "PASS",  # Should be filtered out
        "StatusExtended": "Bucket is private.",
        "Severity": "high",
        "ResourceId": "arn:aws:s3:::my-private-bucket",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Timestamp": "2026-05-07T08:01:00.000000",
        "FindingUniqueId": "prowler-aws-s3_bucket_public_access-123456789012",
    },
    {
        "Provider": "aws",
        "CheckID": "ec2_imdsv2_enabled",
        "CheckTitle": "EC2 IMDSv2 check",
        "ServiceName": "ec2",
        "Status": "FAIL",
        "StatusExtended": "Instance does not require IMDSv2.",
        "Severity": "medium",
        "ResourceId": "arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Timestamp": "2026-05-07T08:02:00.000000",
        "FindingUniqueId": "prowler-aws-ec2_imdsv2-123456789012-i-001",
    },
]


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "prowler.json"
    f.write_text(json.dumps(SAMPLE_FINDINGS))
    return f


def test_load_returns_only_fail_findings(sample_file):
    findings = parser.load(sample_file)
    assert len(findings) == 2
    for f in findings:
        assert f["Status"] in ("FAIL", "WARN")


def test_load_severity_filter(sample_file):
    findings = parser.load(sample_file, severity_filter=["critical"])
    assert len(findings) == 1
    assert findings[0]["CheckID"] == "iam_root_mfa_enabled"


def test_load_rejects_non_list(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"results": []}))
    with pytest.raises(ValueError, match="Expected a JSON array"):
        parser.load(f)


def test_load_example_file():
    example = Path("examples/raw/prowler_sample.json")
    if not example.exists():
        pytest.skip("example file not present")
    findings = parser.load(example)
    assert len(findings) > 0
    for f in findings:
        assert "CheckID" in f
        assert f["Status"] in ("FAIL", "WARN")
