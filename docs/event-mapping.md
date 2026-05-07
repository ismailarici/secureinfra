# SecureInfra — Event Mapping Reference

This document describes how each source tool's raw fields map to SecureOps event schema fields.

The SecureOps event schema is defined at `schemas/event.schema.json`.

---

## Prowler → SecureOps event schema

### Top-level fields

| SecureOps field | Prowler source | Notes |
|-----------------|----------------|-------|
| `event_id` | _(generated)_ | UUID4 generated at normalization time |
| `timestamp` | `Timestamp` | Parsed and converted to UTC ISO 8601 |
| `ingested_at` | _(generated)_ | Time SecureInfra processed the finding |
| `schema_version` | _(hardcoded)_ | Always `"1.0"` |
| `event_type` | _(hardcoded)_ | Always `"vulnerability"` for CSPM findings |
| `severity` | `Severity` | See severity mapping table below |
| `title` | `CheckTitle` | Falls back to `CheckID` if title is absent |
| `description` | `Description` + `StatusExtended` + `Risk` | Concatenated with `\n\n` separators |
| `tags` | _(derived)_ | `["cspm", "prowler", "aws", <ServiceName>, <severity>]` |

### Source object

| SecureOps field | Prowler source | Notes |
|-----------------|----------------|-------|
| `source.component` | _(hardcoded)_ | Always `"secureinfra"` |
| `source.tool` | _(hardcoded)_ | Always `"prowler"` |
| `source.environment` | config.environment | From `config/config.yaml` |
| `source.cloud_provider` | _(hardcoded)_ | Always `"aws"` for v0 |
| `source.region` | `Region` | Per-finding value takes precedence over config |
| `source.account_id` | `AccountId` | Per-finding value takes precedence over config |

### Payload fields (VulnerabilityPayload + CSPM extensions)

Standard VulnerabilityPayload fields:

| SecureOps field | Prowler source | Notes |
|-----------------|----------------|-------|
| `payload.cve_id` | _(null)_ | Not applicable to CSPM findings |
| `payload.cwe_id` | _(null)_ | Not applicable to CSPM findings |
| `payload.affected_file` | _(null)_ | Not applicable to CSPM findings |
| `payload.affected_line` | _(null)_ | Not applicable to CSPM findings |
| `payload.affected_package` | _(null)_ | Not applicable to CSPM findings |
| `payload.affected_version` | _(null)_ | Not applicable to CSPM findings |
| `payload.fixed_version` | _(null)_ | Not applicable to CSPM findings |
| `payload.remediation` | `Remediation.Recommendation.Text` | Human-readable remediation guidance |
| `payload.references` | `Remediation.Recommendation.Url`, `RelatedUrl` | Up to 3 references |

CSPM-specific extensions (additionalProperties: true):

| SecureOps field | Prowler source | Notes |
|-----------------|----------------|-------|
| `payload.check_id` | `CheckID` | Prowler check identifier |
| `payload.status` | `Status` | `FAIL` or `WARN` |
| `payload.status_extended` | `StatusExtended` | Human-readable status detail |
| `payload.resource_id` | `ResourceId` / `ResourceArn` | Affected AWS resource identifier |
| `payload.service` | `ServiceName` | AWS service (iam, s3, ec2, etc.) |
| `payload.risk` | `Risk` | Risk description from Prowler |
| `payload.compliance` | `Compliance[]` | Framework → version → requirement IDs |
| `payload.finding_unique_id` | `FindingUniqueId` | Prowler's globally unique finding ID |

### Severity mapping

| Prowler severity | SecureOps severity |
|------------------|--------------------|
| `critical` | `critical` |
| `high` | `high` |
| `medium` | `medium` |
| `low` | `low` |
| `informational` | `info` |

### Status filtering

Only `FAIL` and `WARN` status findings are normalized and exported.
`PASS` and `MUTED` findings are discarded at parse time.

---

## Future provider mappings

Additional mapping tables will be added here when GCP (Prowler + gcp provider) and Azure support are implemented.
