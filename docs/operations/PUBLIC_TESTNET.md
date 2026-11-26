# Public Testnet Deployment (`TESTNET` Profile)

Use `deploy/docker-compose.testnet.yml` or Kubernetes manifests (`deploy/kubernetes/`) with `NETWORK_PROFILE=TESTNET` and a shared `genesis.json`:

```bash
docker compose -f deploy/docker-compose.testnet.yml up --build -d
```

- Nodes refuse startup if persisted `genesis.json` mismatches `NETWORK_ID` or `NETWORK_PROFILE`.
- Set `NETWORK_ADVERTISED_ADDRESSES` to each host's public IP/DNS multiaddr (`/dns4/<host>/tcp/7001`).
