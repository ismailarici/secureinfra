#!/usr/bin/env python3
"""
End-to-end pipeline test using example data.

Parses examples/raw/prowler_sample.json → normalizes → validates schema → writes to examples/normalized/.
No AWS credentials or Docker required.

Usage:
    python3 scripts/test_pipeline.py
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from prowler.parsers import prowler as parser
from prowler.normalizers import prowler as normalizer
from integrations.secureops import exporter

RAW_SAMPLE = Path("examples/raw/prowler_sample.json")
OUTPUT_DIR = Path("examples/normalized")

SOURCE_META = {
    "environment": "production",
    "account_id": "123456789012",
    "region": "us-east-1",
}


def main():
    print("[test_pipeline] Loading sample Prowler findings...")
    findings = parser.load(RAW_SAMPLE)
    print(f"[test_pipeline] {len(findings)} findings parsed")

    print("[test_pipeline] Normalizing to SecureOps event schema...")
    events = normalizer.normalise(findings, SOURCE_META)
    print(f"[test_pipeline] {len(events)} events produced")

    print("[test_pipeline] Validating schema and writing to examples/normalized/...")
    written = exporter.export_local(events, OUTPUT_DIR, validate_schema=True)
    print(f"[test_pipeline] {len(written)} files written")

    print("\n[test_pipeline] Event summary:")
    for e in events:
        print(f"  [{e['severity'].upper():8s}] {e['title'][:72]}")

    print(f"\n[test_pipeline] PASS — pipeline ran end-to-end cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
