# Global Deployment Architecture

Deployment manifests are provided under `deploy/`:
- **Container Images**: `deploy/Dockerfile.node` & `deploy/Dockerfile.api`
- **Multi-Node Compose**: `deploy/docker-compose.testnet.yml` (4-node testnet) & `deploy/docker-compose.public.yml` (public node + Nginx TLS proxy)
- **Reverse Proxies**: `deploy/reverse-proxy/nginx.conf` (WebSocket upgrade + TLS termination + rate limiting) & `deploy/reverse-proxy/Caddyfile`
- **Systemd Unit**: `deploy/systemd/vnetwork-node.service`
- **Kubernetes**: `deploy/kubernetes/{namespace.yaml, bootstrap-statefulset.yaml, validator-statefulset.yaml, api-service.yaml, ingress.yaml}`

Operators supply DNS domains, TLS certificates, persistent volumes, and distinct `genesis.json` validator keys per environment (`TESTNET` vs `PRODUCTION`).
