"""Integration test: full parser → normalizer → exporter pipeline."""

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from prowler.parsers import prowler as parser
from prowler.normalizers import prowler as normalizer
from integrations.secureops import exporter

RAW_SAMPLE = Path("examples/raw/prowler_sample.json")

SOURCE_META = {
    "environment": "production",
    "account_id": "123456789012",
    "region": "us-east-1",
}


@pytest.mark.skipif(not RAW_SAMPLE.exists(), reason="example data not present")
def test_full_pipeline_parses_and_normalizes(tmp_path):
    findings = parser.load(RAW_SAMPLE)
    assert len(findings) > 0

    events = normalizer.normalise(findings, SOURCE_META)
    assert len(events) == len(findings)

    written = exporter.export_local(events, tmp_path, validate_schema=True)
    # Expect one file per event + one JSONL
    assert len(written) == len(events) + 1


@pytest.mark.skipif(not RAW_SAMPLE.exists(), reason="example data not present")
def test_all_events_pass_schema_validation(tmp_path):
    findings = parser.load(RAW_SAMPLE)
    events = normalizer.normalise(findings, SOURCE_META)

    import jsonschema
    schema_path = Path("schemas/event.schema.json")
    with open(schema_path) as f:
        schema = json.load(f)

    for event in events:
        jsonschema.validate(instance=event, schema=schema)


@pytest.mark.skipif(not RAW_SAMPLE.exists(), reason="example data not present")
def test_all_events_have_secureinfra_component():
    findings = parser.load(RAW_SAMPLE)
    events = normalizer.normalise(findings, SOURCE_META)
    for e in events:
        assert e["source"]["component"] == "secureinfra"
        assert e["source"]["tool"] == "prowler"
