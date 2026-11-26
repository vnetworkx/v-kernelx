# Network Monitoring Runbook

Use `./scripts/health-check.sh` or scrape `GET /metrics` (Prometheus exposition), `GET /healthz`, `GET /readyz`, `GET /v1/consensus/status`, and `GET /v1/ledger/proofs` across validator and full nodes to verify uniform `height`, `state_root`, and `chain_valid: true`.
