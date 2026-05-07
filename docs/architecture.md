# SecureInfra — Architecture

## Role in the platform

SecureInfra is the infrastructure and cloud security layer of a three-component modular security platform:

```
SecurePipe  ──┐
              ├──► SecureOps (SIEM/XDR + alerting + audit evidence)
SecureInfra ──┘
```

SecureInfra does not route, alert, or aggregate events. It is a **producer only**. Its job is to:
1. Execute cloud posture scans against cloud accounts
2. Parse and validate the raw tool output
3. Normalize findings into the SecureOps event schema
4. Export normalized events for SecureOps to consume

---

## Event flow

```
Cloud Account (AWS)
       │
       ▼
  run_prowler.sh
  (Docker or native Prowler)
       │
       ▼
  outputs/prowler/prowler_output.json     ← raw Prowler JSON
       │
       ▼
  prowler/parsers/prowler.py              ← loads, filters by status + severity
       │
       ▼
  prowler/normalizers/prowler.py          ← maps to SecureOps event schema
       │
       ▼
  integrations/secureops/exporter.py     ← validates schema, writes JSON + JSONL
       │
       ▼
  outputs/normalized/                    ← SecureOps-ready events
       │
       ▼
  [SecureOps ingestion — future]
```

---

## Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `prowler/runner/` | Executes Prowler (Docker or native); returns path to output JSON |
| `prowler/parsers/` | Loads raw Prowler JSON; filters by status (FAIL/WARN) and severity |
| `prowler/normalizers/` | Maps Prowler fields to SecureOps event schema |
| `integrations/secureops/` | Validates and writes events to disk; future API forwarding placeholder |
| `config/` | All behavior is driven by config.yaml; no hardcoded values in code |
| `schemas/` | Event schema definition (mirrors SecureOps normalizer/schemas/event.schema.json) |

---

## Portability approach

Provider-specific logic is isolated to individual modules under `prowler/`. The core interfaces — the event schema, the exporter, and the config structure — are provider-neutral.

Adding GCP or Azure support means:
1. Adding a `gcp/` or `azure/` directory mirroring the `prowler/` structure
2. Adding a new runner, parser, and normalizer for the target tool
3. The exporter, schema, and SecureOps integration remain unchanged

The shared event schema is the portability contract. As long as all normalizers produce valid SecureOps schema events, SecureOps can consume them without knowing which cloud or tool produced them.

---

## Config-driven design

All organizational, environmental, and credential information lives in `config/config.yaml`, which is git-ignored. The codebase contains no hardcoded account IDs, regions, organization names, or credentials.

Template configs live in `config/example.*.yaml`.

---

## Provider onboarding strategy

To add a new cloud provider or tool:

1. Create `<provider>/runner/<runner>.py` — executes the scan tool, returns output path
2. Create `<provider>/parsers/<parser>.py` — loads raw output, returns list of raw findings
3. Create `<provider>/normalizers/<normalizer>.py` — maps to SecureOps event schema
4. Add the provider to `config/example.<provider>.yaml`
5. Add tests under `tests/`

The normalizer output must be a list of dicts conforming to `schemas/event.schema.json`.

---

## Relationship with SecureOps

SecureOps expects to receive events in the shared event schema format. SecureInfra produces those events. In v0, the handoff is via the local filesystem (`outputs/normalized/`). In future versions, SecureInfra will forward events directly to the SecureOps HTTP API.

The schema version is locked at `1.0`. Any breaking schema changes require coordination across both projects.

---

## Constraints and principles

- No SIEM logic in SecureInfra — routing, alerting, and storage belong in SecureOps
- No hardcoding — no org names, account IDs, or credentials in code
- No Kafka, no message queues, no agent sprawl — simple Python pipeline
- Raw findings are always preserved in the `raw` field for audit purposes
- Schema validation happens at export time — invalid events are logged and skipped
