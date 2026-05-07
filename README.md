# SecureInfra

**Infrastructure and cloud security normalization layer.**

SecureInfra scans your cloud accounts for security misconfigurations, normalizes every finding into a provider-neutral event format, and exports them ready for [SecureOps](https://github.com/ismailarici/secureops) to ingest.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

---

## Part of a modular open-source security platform

| Component | What it does |
|-----------|-------------|
| [**SecurePipe**](https://github.com/ismailarici/securepipe) | Application security — SAST, SCA, DAST, CI/CD scanning |
| **SecureInfra** ← you are here | Infrastructure security — cloud posture scanning and normalization |
| [**SecureOps**](https://github.com/ismailarici/secureops) | SIEM/XDR layer — ingests SecurePipe + SecureInfra, routes to Wazuh, alerts, produces audit evidence |

SecureInfra sits between your cloud accounts and SecureOps. It does **not** alert, route, or store events — it is a **producer** only.

---

## What it does

1. Runs [Prowler](https://github.com/prowler-cloud/prowler) against your AWS account (via Docker or native)
2. Parses and filters the raw findings (FAIL/WARN, above your configured severity threshold)
3. Normalizes every finding into the shared SecureOps event schema (v1.0)
4. Validates each event against the JSON schema
5. Writes normalized events to disk — one JSON file per finding plus a JSONL bundle

SecureOps can then pick up those files and route them to Wazuh, DefectDojo, Slack, and email.

---

## Supported providers and tools

| Cloud | Scanner | Status |
|-------|---------|--------|
| AWS | Prowler | Supported |
| GCP | Prowler | Roadmap |
| Azure | Prowler | Roadmap |

---

## How the pipeline works

```
AWS Account
    │
    ▼
scripts/run_prowler.sh          ← runs Prowler via Docker
    │
    ▼
outputs/prowler/prowler_output.json   ← raw Prowler JSON

    │
    ▼
prowler/parsers/prowler.py      ← loads + filters (FAIL/WARN, severity)
    │
    ▼
prowler/normalizers/prowler.py  ← maps to SecureOps event schema
    │
    ▼
integrations/secureops/exporter.py   ← validates schema, writes files
    │
    ▼
outputs/normalized/             ← SecureOps-ready events (JSON + JSONL)
```

---

## Quickstart

### Requirements

- Python 3.10+
- Docker (for running Prowler) — or Prowler installed natively
- Valid AWS credentials (environment variables or `~/.aws/credentials`)

### 1. Clone and install

```bash
git clone https://github.com/ismailarici/secureinfra.git
cd secureinfra
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/example.aws.yaml config/config.yaml
```

Edit `config/config.yaml` with your AWS account details:

```yaml
organization: your-org
environment: production

aws:
  account_id: "123456789012"
  region: us-east-1
  profile: default

prowler:
  enabled: true
  severity_filter: [critical, high, medium]
```

### 3. Run a scan

```bash
bash scripts/run_prowler.sh
```

This runs Prowler via Docker and writes raw findings to `outputs/prowler/prowler_output.json`.

### 4. Normalize findings

```bash
python3 scripts/normalize_findings.py \
  --input outputs/prowler/prowler_output.json \
  --config config/config.yaml \
  --output outputs/normalized
```

Normalized events land in `outputs/normalized/` — one JSON per finding plus a `_events.jsonl` bundle.

### 5. Test without AWS credentials

Run the full pipeline against the bundled sample data (no Docker, no AWS needed):

```bash
python3 scripts/test_pipeline.py
```

Expected output:

```
[test_pipeline] Loading sample Prowler findings...
[test_pipeline] 4 findings parsed
[test_pipeline] Normalizing to SecureOps event schema...
[test_pipeline] 4 events produced
[test_pipeline] Validating schema and writing to examples/normalized/...
[test_pipeline] 5 files written

[test_pipeline] Event summary:
  [CRITICAL] Ensure MFA is enabled for the root account
  [HIGH    ] Ensure S3 buckets do not allow public access
  [MEDIUM  ] Ensure CloudTrail is enabled in all regions
  [MEDIUM  ] Ensure EC2 instances use IMDSv2

[test_pipeline] PASS — pipeline ran end-to-end cleanly
```

---

## Event schema

Every normalized finding is a JSON object conforming to the [SecureOps event schema v1.0](schemas/event.schema.json).

Example normalized event:

```json
{
  "event_id": "a3f1c2d4-0001-4b5e-9f3a-1234abcd5678",
  "timestamp": "2026-05-07T08:00:00+00:00",
  "ingested_at": "2026-05-07T08:00:01+00:00",
  "schema_version": "1.0",
  "source": {
    "component": "secureinfra",
    "tool": "prowler",
    "environment": "production",
    "cloud_provider": "aws",
    "region": "us-east-1",
    "account_id": "123456789012"
  },
  "event_type": "vulnerability",
  "severity": "critical",
  "title": "Ensure MFA is enabled for the root account",
  "description": "The root account is the most privileged user in an AWS account...",
  "tags": ["cspm", "prowler", "aws", "iam", "critical"],
  "payload": {
    "remediation": "Enable MFA for the root account via IAM → Security credentials.",
    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/..."],
    "check_id": "iam_root_mfa_enabled",
    "status": "FAIL",
    "status_extended": "MFA is not enabled for the root account.",
    "resource_id": "arn:aws:iam::123456789012:root",
    "service": "iam",
    "compliance": [
      {
        "framework": "CIS-AWS-Foundations-Benchmark",
        "version": "1.4",
        "requirements": ["1.5"]
      }
    ],
    "finding_unique_id": "prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1"
  }
}
```

See [docs/event-mapping.md](docs/event-mapping.md) for a full field-by-field mapping table.

---

## Running tests

```bash
python3 -m pytest tests/ -v
```

```
22 passed in 0.10s
```

Tests cover: parser filtering, severity mapping, normalizer field mapping, compliance extraction, schema validation, and full end-to-end pipeline.

---

## Project structure

```
secureinfra/
├── config/                  # Config templates (config.yaml is git-ignored)
│   ├── example.aws.yaml
│   ├── example.gcp.yaml     # placeholder — GCP on roadmap
│   └── example.azure.yaml   # placeholder — Azure on roadmap
├── docs/
│   ├── architecture.md      # Design, event flow, portability approach
│   ├── event-mapping.md     # Prowler field → SecureOps schema mapping
│   └── roadmap.md           # Planned future capabilities
├── prowler/
│   ├── runner/              # Executes Prowler (Docker or native)
│   ├── parsers/             # Loads + filters raw Prowler JSON
│   └── normalizers/         # Maps findings to SecureOps event schema
├── integrations/
│   └── secureops/           # Local export + future API forwarding
├── examples/
│   ├── raw/                 # Sample Prowler output
│   └── normalized/          # Sample normalized SecureOps events
├── schemas/
│   └── event.schema.json    # SecureOps event schema v1.0
├── scripts/
│   ├── run_prowler.sh       # Run Prowler via Docker
│   ├── normalize_findings.py # CLI: parse + normalize + export
│   └── test_pipeline.py     # End-to-end test using example data
├── tests/                   # Unit + integration tests (pytest)
├── outputs/                 # Runtime output — git-ignored
├── LICENSE
└── README.md
```

---

## Design principles

- **Producer only** — SecureInfra generates normalized findings. Routing, alerting, and storage belong in SecureOps.
- **Config-driven** — no hardcoded account IDs, regions, or org names in code.
- **Portable schema** — the event schema is provider-neutral. Adding GCP or Azure means adding a new normalizer module; the exporter and SecureOps integration stay unchanged.
- **Audit-ready** — raw Prowler findings are preserved in the `raw` field of every event.
- **No overengineering** — no Kafka, no queues, no agents. A simple Python pipeline you can run in CI or on a schedule.

---

## Connecting to SecureOps

Once normalized events are in `outputs/normalized/`, point SecureOps at that directory:

```bash
# In your SecureOps project:
python3 -m normalizer.main \
  --input /path/to/secureinfra/outputs/normalized \
  --config config/config.yaml
```

SecureOps will ingest the JSONL bundle, route findings to Wazuh and DefectDojo, and write audit evidence.

---

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for planned features including GCP/Azure support, drift detection, CIS benchmark tagging, and host-based scanning.

---

## License

[MIT](LICENSE) — © 2026 Ismail Arici
