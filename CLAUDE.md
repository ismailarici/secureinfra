# SecureInfra — Project Instructions

## Git identity

All commits and pushes must be authored and pushed as **ismailarici**.
Never use Claude as an author, committer, or co-author.
Never add `Co-Authored-By` lines to any commit message.

## Scope

SecureInfra is an infrastructure and cloud security normalization layer.
It runs cloud posture checks (CSPM) and normalizes findings into the SecureOps event schema.
It does NOT implement SIEM logic, alerting, or orchestration — that belongs in SecureOps.

## Architecture rules

- SecureInfra is a **producer** of normalized findings. It does not route, alert, or store events.
- Everything must be portable — avoid hardcoding AWS/GCP/Azure assumptions in core modules.
- All behaviour is config-driven via `config/config.yaml` (never committed — see `.gitignore`).
- All outputs conform to the SecureOps event schema (v1.0) defined in `schemas/event.schema.json`.
- Keep modules loosely coupled: runner → parser → normalizer → exporter.
- No Kafka, no microservice sprawl — keep it clean Python.

## v0 scope

v0 supports AWS + Prowler only. Do not add GCP/Azure/OpenVAS/network scanning in v0.

## Commit style

- Short imperative subject line (under 72 characters)
- No trailing summaries or change lists in the body — the diff speaks for itself
- No `Co-Authored-By` lines
