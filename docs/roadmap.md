# SecureInfra — Roadmap

v0 covers AWS + Prowler only. This document lists planned future capabilities.

---

## v1 — GCP support

- Add `gcp/runner/`, `gcp/parsers/`, `gcp/normalizers/`
- Prowler supports GCP natively as of v3 — reuse the same Docker image
- Update config schema for GCP project/region fields
- Add `config/example.gcp.yaml` with full GCP support

---

## v1 — Azure support

- Add `azure/runner/`, `azure/parsers/`, `azure/normalizers/`
- Prowler supports Azure natively as of v3
- Update config schema for Azure subscription/tenant fields
- Add `config/example.azure.yaml` with full Azure support

---

## v1 — SecureOps HTTP API integration

- Implement `integrations/secureops/exporter.export_secureops_api()`
- Configure endpoint and API key in `config/config.yaml`
- Retry logic for transient failures
- Batch forwarding to reduce HTTP overhead

---

## v2 — CIS benchmark support

- Add CIS benchmark compliance tagging to normalizer output
- Map Prowler compliance fields to CIS control IDs
- Export compliance summary alongside findings

---

## v2 — Infrastructure drift detection

- Compare Prowler findings across consecutive runs
- Flag new findings, resolved findings, and persistent findings
- Export drift summary as a separate event type

---

## v2 — Terraform / IaC posture analysis

- Integrate Checkov or tfsec for IaC scanning
- Normalize IaC findings to the same event schema
- Link IaC issues to their corresponding live resource findings

---

## v3 — Host-based scanning

- Integrate OpenVAS or Nessus (free/community editions) for host vulnerability scanning
- Add `hostscan/runner/`, `hostscan/parsers/`, `hostscan/normalizers/`
- Map CVE findings to the `vulnerability` event type

---

## v3 — CSPM dashboards

- HTML report generation for CSPM findings (similar to SecurePipe report format)
- Severity trend graphs across scan runs
- Per-service breakdown view

---

## v3 — Kubernetes security

- Integrate kube-bench for CIS Kubernetes benchmark
- Integrate Trivy for Kubernetes cluster scanning
- Normalize findings to SecureOps event schema

---

## Long-term — Multi-account / multi-org support

- Config-driven account list for org-wide scanning
- Per-account finding aggregation
- Org-level summary export
