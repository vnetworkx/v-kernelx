# Production Deployment (`PRODUCTION` Profile)

1. Generate dedicated hardware/isolated keys per validator via `vnetwork-node init-key --validator`.
2. Build `genesis.json` with `profile: "PRODUCTION"` and `allow_bootstrap_atlas: false`. (`devnet` network IDs and `ATLAS` fixtures are rejected unless explicitly authorized in genesis.)
3. Deploy via `deploy/kubernetes/`, `deploy/systemd/vnetwork-node.service`, or `deploy/docker-compose.public.yml` behind `deploy/reverse-proxy/nginx.conf` or `Caddyfile` with TLS certificates and DNS records.
4. Expose only TLS-terminated API/WebSocket ports (`443`) and P2P port (`7001`).
