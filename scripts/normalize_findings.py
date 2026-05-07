#!/usr/bin/env python3
"""
Normalize a Prowler JSON output file into SecureOps-compatible events.

Usage:
    python3 scripts/normalize_findings.py \
        --input outputs/prowler/prowler_output.json \
        --config config/config.yaml \
        --output outputs/normalized
"""

import sys
import json
import click
import yaml
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from prowler.parsers import prowler as parser
from prowler.normalizers import prowler as normalizer
from integrations.secureops import exporter


@click.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Path to Prowler JSON output file")
@click.option("--config", "config_path", default="config/config.yaml", type=click.Path(), help="Path to config.yaml")
@click.option("--output", "output_dir", default="outputs/normalized", help="Output directory for normalized events")
@click.option("--no-validate", is_flag=True, default=False, help="Skip schema validation")
def main(input_path, config_path, output_dir, no_validate):
    config = {}
    cfg_path = Path(config_path)
    if cfg_path.exists():
        with open(cfg_path) as f:
            config = yaml.safe_load(f) or {}
    else:
        print(f"[warn] Config not found at {config_path} — using defaults")

    source_meta = {
        "environment": config.get("environment"),
        "account_id": config.get("aws", {}).get("account_id"),
        "region": config.get("aws", {}).get("region"),
    }

    severity_filter = config.get("prowler", {}).get("severity_filter")

    print(f"[normalize] Loading findings from {input_path}")
    findings = parser.load(Path(input_path), severity_filter=severity_filter)
    print(f"[normalize] {len(findings)} findings loaded (after severity filter)")

    events = normalizer.normalise(findings, source_meta)
    print(f"[normalize] {len(events)} events normalized")

    out = Path(output_dir)
    written = exporter.export_local(events, out, validate_schema=not no_validate)
    print(f"[normalize] Written {len(written)} files to {out}/")

    # Summary
    by_severity = {}
    for e in events:
        s = e.get("severity", "unknown")
        by_severity[s] = by_severity.get(s, 0) + 1
    print(f"[normalize] Severity breakdown: {json.dumps(by_severity)}")


if __name__ == "__main__":
    main()
