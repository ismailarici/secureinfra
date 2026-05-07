"""Unit tests for prowler.normalizers.prowler."""

import sys
import uuid
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from prowler.normalizers import prowler as normalizer


RAW_FINDING = {
    "Provider": "aws",
    "CheckID": "iam_root_mfa_enabled",
    "CheckTitle": "Ensure MFA is enabled for the root account",
    "ServiceName": "iam",
    "Status": "FAIL",
    "StatusExtended": "MFA is not enabled for the root account.",
    "Severity": "critical",
    "ResourceId": "arn:aws:iam::123456789012:root",
    "ResourceArn": "arn:aws:iam::123456789012:root",
    "Description": "The root account is the most privileged user in an AWS account.",
    "Risk": "An attacker with root credentials has full account access.",
    "RelatedUrl": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
    "Remediation": {
        "Code": {},
        "Recommendation": {
            "Text": "Enable MFA for the root account.",
            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
        },
    },
    "Compliance": [
        {
            "Framework": "CIS-AWS-Foundations-Benchmark",
            "Version": "1.4",
            "Requirements": [{"Id": "1.5", "Description": "Ensure MFA for root"}],
        }
    ],
    "Timestamp": "2026-05-07T08:00:00.000000",
    "AccountId": "123456789012",
    "Region": "us-east-1",
    "FindingUniqueId": "prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1",
}

SOURCE_META = {
    "environment": "production",
    "account_id": "123456789012",
    "region": "us-east-1",
}


def test_normalise_produces_one_event_per_finding():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert len(events) == 1


def test_event_has_required_fields():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    e = events[0]
    for field in ("event_id", "timestamp", "ingested_at", "schema_version", "source", "event_type", "severity", "title", "payload"):
        assert field in e, f"Missing required field: {field}"


def test_event_id_is_uuid(  ):
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    uuid.UUID(events[0]["event_id"])  # raises if invalid


def test_severity_mapping():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert events[0]["severity"] == "critical"


def test_source_component_is_secureinfra():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert events[0]["source"]["component"] == "secureinfra"
    assert events[0]["source"]["tool"] == "prowler"
    assert events[0]["source"]["cloud_provider"] == "aws"


def test_per_finding_account_and_region_override_source_meta():
    meta = {"environment": "staging", "account_id": "000000000000", "region": "eu-west-1"}
    events = normalizer.normalise([RAW_FINDING], meta)
    e = events[0]
    # Per-finding values from Prowler JSON take precedence
    assert e["source"]["account_id"] == "123456789012"
    assert e["source"]["region"] == "us-east-1"


def test_schema_version_is_1_0():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert events[0]["schema_version"] == "1.0"


def test_event_type_is_vulnerability():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert events[0]["event_type"] == "vulnerability"


def test_payload_contains_cspm_extensions():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    payload = events[0]["payload"]
    assert payload["check_id"] == "iam_root_mfa_enabled"
    assert payload["status"] == "FAIL"
    assert payload["resource_id"] == "arn:aws:iam::123456789012:root"


def test_compliance_mapping_preserved():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    compliance = events[0]["payload"]["compliance"]
    assert len(compliance) == 1
    assert compliance[0]["framework"] == "CIS-AWS-Foundations-Benchmark"
    assert "1.5" in compliance[0]["requirements"]


def test_remediation_extracted():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    payload = events[0]["payload"]
    assert "MFA" in payload["remediation"]


def test_tags_include_cspm_and_service():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    tags = events[0]["tags"]
    assert "cspm" in tags
    assert "prowler" in tags
    assert "iam" in tags


def test_raw_is_preserved():
    events = normalizer.normalise([RAW_FINDING], SOURCE_META)
    assert events[0]["raw"] == RAW_FINDING


def test_informational_severity_maps_to_info():
    finding = dict(RAW_FINDING, Severity="informational", Status="FAIL")
    events = normalizer.normalise([finding], SOURCE_META)
    assert events[0]["severity"] == "info"


def test_empty_findings_returns_empty_list():
    events = normalizer.normalise([], SOURCE_META)
    assert events == []
