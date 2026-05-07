"""Converts parsed Prowler findings into SecureOps-compatible event schema objects."""

import uuid
from datetime import datetime, timezone

# Maps Prowler severity strings → SecureOps severity enum
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def normalise(findings: list[dict], source_meta: dict) -> list[dict]:
    """
    Converts a list of raw Prowler findings into SecureOps event schema dicts.

    source_meta keys (all optional):
      environment   — from config (e.g. "production")
      account_id    — AWS account ID (overridden per-finding if present)
      region        — AWS region (overridden per-finding if present)
    """
    now = datetime.now(timezone.utc).isoformat()
    events = []

    for finding in findings:
        event = _normalise_one(finding, source_meta, now)
        events.append(event)

    return events


def _normalise_one(f: dict, source_meta: dict, ingested_at: str) -> dict:
    severity = _SEV_MAP.get((f.get("Severity") or "informational").lower(), "info")

    # Prefer per-finding timestamp; fall back to ingestion time
    raw_ts = f.get("Timestamp")
    timestamp = _parse_timestamp(raw_ts) if raw_ts else ingested_at

    account_id = f.get("AccountId") or source_meta.get("account_id")
    region = f.get("Region") or source_meta.get("region")
    check_id = f.get("CheckID", "unknown")
    resource_id = f.get("ResourceId") or f.get("ResourceArn")
    service = f.get("ServiceName", "")

    title = f.get("CheckTitle") or check_id
    description = _build_description(f)
    remediation = _extract_remediation_text(f)
    references = _extract_references(f)
    compliance = _extract_compliance(f)
    tags = _build_tags(f)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "ingested_at": ingested_at,
        "schema_version": "1.0",
        "source": {
            "component": "secureinfra",
            "tool": "prowler",
            "environment": source_meta.get("environment"),
            "cloud_provider": "aws",
            "region": region,
            "account_id": account_id,
        },
        "event_type": "vulnerability",
        "severity": severity,
        "title": title,
        "description": description,
        "tags": tags,
        "payload": {
            "cve_id": None,
            "cwe_id": None,
            "affected_file": None,
            "affected_line": None,
            "affected_package": None,
            "affected_version": None,
            "fixed_version": None,
            "remediation": remediation,
            "references": references,
            # CSPM-specific extensions (additionalProperties: true in schema)
            "check_id": check_id,
            "status": f.get("Status"),
            "status_extended": f.get("StatusExtended"),
            "resource_id": resource_id,
            "service": service,
            "risk": f.get("Risk"),
            "compliance": compliance,
            "finding_unique_id": f.get("FindingUniqueId"),
        },
        "raw": f,
    }


def _parse_timestamp(raw: str) -> str:
    """Normalise Prowler timestamp to ISO 8601 UTC."""
    try:
        # Prowler v3/v4 format: "2024-01-15T10:30:00.000000"
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc).isoformat()


def _build_description(f: dict) -> str | None:
    parts = []
    if f.get("Description"):
        parts.append(f["Description"])
    if f.get("StatusExtended"):
        parts.append(f"Status: {f['StatusExtended']}")
    if f.get("Risk"):
        parts.append(f"Risk: {f['Risk']}")
    return "\n\n".join(parts) if parts else None


def _extract_remediation_text(f: dict) -> str | None:
    remediation = f.get("Remediation") or {}
    rec = remediation.get("Recommendation") or {}
    return rec.get("Text") or None


def _extract_references(f: dict) -> list[str]:
    refs = []
    remediation = f.get("Remediation") or {}
    rec = remediation.get("Recommendation") or {}
    url = rec.get("Url")
    if url:
        refs.append(url)
    related = f.get("RelatedUrl")
    if related and related not in refs:
        refs.append(related)
    return refs[:3]


def _extract_compliance(f: dict) -> list[dict]:
    raw = f.get("Compliance") or []
    out = []
    for entry in raw:
        framework = entry.get("Framework")
        version = entry.get("Version")
        requirements = [
            r.get("Id") for r in (entry.get("Requirements") or []) if r.get("Id")
        ]
        if framework:
            out.append({"framework": framework, "version": version, "requirements": requirements})
    return out


def _build_tags(f: dict) -> list[str]:
    tags = ["cspm", "prowler", "aws"]
    service = f.get("ServiceName")
    if service:
        tags.append(service.lower())
    severity = (f.get("Severity") or "").lower()
    if severity:
        tags.append(severity)
    return tags
