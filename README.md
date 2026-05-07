# SecureInfra

Portable infrastructure and cloud security normalization layer.

SecureInfra runs cloud posture checks against your AWS (and future GCP/Azure) environments, normalizes the findings into a provider-neutral event schema, and exports them for consumption by SecureOps.

---

## Part of a modular security platform

| Component | Role |
|-----------|------|
| **SecurePipe** | Application security — SAST, SCA, DAST, CI/CD scanning |
| **SecureInfra** | Infrastructure security — CSPM, cloud posture, infra vulnerability normalization |
| **SecureOps** | SIEM/XDR + orchestration — ingests SecurePipe and SecureInfra outputs, routes to Wazuh, alerts, produces audit evidence |

SecureInfra sits between your cloud accounts and SecureOps. It does not implement SIEM logic. It is a **producer** only.

---

## Design philosophy

- **Portable** — provider-neutral event schema; cloud specifics are isolated to provider modules
- **Config-driven** — organization, account, environment, and output paths in `config/config.yaml`
- **Modular** — runner → parser → normalizer → exporter; each step is independently replaceable
- **Minimal** — no Kafka, no queues, no agent sprawl; runs as a simple Python pipeline
- **Audit-ready** — raw findings preserved alongside normalized events

---

## Supported providers (v0)

| Provider | Status |
|----------|--------|
| AWS | Supported |
| GCP | Roadmap |
| Azure | Roadmap |

## Supported scanners/tools (v0)

| Tool | Provider | Status |
|------|----------|--------|
| Prowler | AWS | Supported |
| OpenVAS | Any | Roadmap |
| Nessus | Any | Roadmap |

---

## Current scope (v0)

- AWS account scanning via Prowler
- Prowler JSON output parsing
- Normalization to SecureOps event schema
- Local file export (JSONL and per-event JSON)
- Schema validation against SecureOps event schema

## Future scope

See [docs/roadmap.md](docs/roadmap.md).

---

## Architecture overview

```
┌─────────────────────────────────────────────────────┐
│                     SecureInfra                      │
│                                                     │
│  config/config.yaml                                 │
│         │                                           │
│         ▼                                           │
│  prowler/runner  ──► Prowler (Docker/native)        │
│         │                                           │
│         ▼                                           │
│  prowler/parsers ──► raw finding list               │
│         │                                           │
│         ▼                                           │
│  prowler/normalizers ──► SecureOps event schema     │
│         │                                           │
│         ▼                                           │
│  integrations/secureops ──► outputs/ (local JSON)   │
│                         └──► [future] SecureOps API  │
└─────────────────────────────────────────────────────┘
```

Event schema: `schemas/event.schema.json` (mirrors SecureOps v1.0 schema)

---

## Quickstart

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/example.aws.yaml config/config.yaml
# Edit config/config.yaml with your AWS account details
```

### 3. Run Prowler

Requires Docker or Prowler installed natively.

```bash
bash scripts/run_prowler.sh
```

### 4. Normalize findings

```bash
python3 scripts/normalize_findings.py \
  --input outputs/prowler/prowler_output.json \
  --config config/config.yaml \
  --output outputs/normalized
```

### 5. Run end-to-end test against example data

```bash
python3 scripts/test_pipeline.py
```

---

## Configuration reference

See `config/example.aws.yaml` for a fully annotated example.

Key sections:

```yaml
organization: acme-corp
environment: production

aws:
  account_id: "123456789012"
  region: us-east-1

prowler:
  enabled: true
  severity_filter: [critical, high, medium]

outputs:
  local_path: outputs/normalized

integrations:
  secureops:
    enabled: false
    endpoint: null     # TODO: set when SecureOps API is available
```

---

## Project structure

```
secureinfra/
├── config/            # Config templates (real config.yaml is git-ignored)
├── docs/              # Architecture, roadmap, event-mapping docs
├── prowler/
│   ├── runner/        # Executes Prowler (Docker or native)
│   ├── parsers/       # Loads and validates raw Prowler JSON
│   └── normalizers/   # Converts Prowler findings → SecureOps events
├── integrations/
│   └── secureops/     # Local export + future API integration
├── examples/
│   ├── raw/           # Sample Prowler output
│   └── normalized/    # Sample normalized SecureOps events
├── outputs/           # Runtime output (git-ignored)
├── schemas/           # SecureOps event schema (v1.0)
├── scripts/           # Run, normalize, test scripts
└── tests/             # Parser and normalizer unit tests
```

---

## Running tests

```bash
python3 -m pytest tests/ -v
```

---

## Contributing

This project is part of a private modular security platform. All commits must be pushed as **ismailarici**.
