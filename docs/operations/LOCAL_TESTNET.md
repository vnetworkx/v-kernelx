# Local Testnet Operations

Start a 4-validator persistent local `libp2p` cluster:

```bash
DEVNET_CLEAN=1 ./scripts/devnet-up.sh
./scripts/health-check.sh
./scripts/test-all-sdks.sh
./scripts/devnet-down.sh
```

To run the complete end-to-end acceptance suite (including BFT fault injection & WAL restart catch-up sync):

```bash
./scripts/test-network.sh
```
