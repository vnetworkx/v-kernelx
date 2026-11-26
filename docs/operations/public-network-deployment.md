# Public Network Deployment Checklist

See `GLOBAL_DEPLOYMENT.md`, `PUBLIC_TESTNET.md`, and `PRODUCTION_DEPLOYMENT.md` for Docker Compose, Systemd, and Kubernetes manifests under `deploy/`.
Required manual infrastructure steps:
1. Provision DNS A/AAAA records for bootstrap seeds and public API gateways.
2. Issue TLS certificates mounted at the reverse proxy (`deploy/reverse-proxy/nginx.conf` or `Caddyfile`).
3. Distribute distinct validator identities (`vnetwork-node init-key --validator`) and finalized `genesis.json`.
