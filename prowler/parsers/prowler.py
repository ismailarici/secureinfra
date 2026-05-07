"""Loads and validates raw Prowler JSON output."""

import json
from pathlib import Path


# Only normalize findings in these statuses. PASS and MUTED are informational.
_ACTIVE_STATUSES = {"FAIL", "WARN"}

# Prowler v3/v4 severity values (lowercase)
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def load(path: Path, severity_filter: list[str] | None = None) -> list[dict]:
    """
    Loads a Prowler JSON output file and returns a filtered list of raw findings.

    Prowler outputs a JSON array where each element is a single check result.
    Only FAIL and WARN status findings are returned by default.
    severity_filter restricts findings to the specified severity levels.
    """
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}, got {type(data).__name__}")

    findings = []
    for item in data:
        status = (item.get("Status") or "").upper()
        if status not in _ACTIVE_STATUSES:
            continue

        severity = (item.get("Severity") or "informational").lower()
        if severity not in _VALID_SEVERITIES:
            severity = "informational"

        if severity_filter:
            # Prowler "informational" maps to our "info" — handle both spellings
            normalised_filter = [s.replace("info", "informational") for s in severity_filter]
            if severity not in normalised_filter:
                continue

        findings.append(item)

    return findings
