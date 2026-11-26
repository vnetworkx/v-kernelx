#!/usr/bin/env tsx
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AtlasKernel } from "./ts/src/atlas_kernel.ts";
import { formatTokenUnits } from "./ts/src/token.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(process.env.ATLAS_DATA_DIR || path.join(__dirname, "data"));
const pidFile = path.join(dataDir, "atlas-node.pid");
const logFile = path.join(dataDir, "atlas-node.log");

function argFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

function isPidRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function startNode(): Promise<void> {
  fs.mkdirSync(dataDir, { recursive: true });
  if (fs.existsSync(pidFile)) {
    const existing = Number(fs.readFileSync(pidFile, "utf8").trim());
    if (Number.isInteger(existing) && existing > 0 && isPidRunning(existing)) {
      console.log(JSON.stringify({ status: "already_running", pid: existing }));
      return;
    }
    fs.unlinkSync(pidFile);
  }
  const port = String(Number(process.env.PORT) || 3000);
  const outFd = fs.openSync(logFile, "a");
  const child = spawn("npx", ["next", "start", "-p", port, "-H", "0.0.0.0"], {
    cwd: __dirname,
    detached: true,
    stdio: ["ignore", outFd, outFd],
    env: { ...process.env, ATLAS_DATA_DIR: dataDir, PORT: port },
  });
  child.unref();
  if (!child.pid) {
    throw new Error("failed to spawn atlas node");
  }
  fs.writeFileSync(pidFile, String(child.pid));
  console.log(JSON.stringify({ status: "started", pid: child.pid, log_file: logFile, port: Number(port) }));
}

function stopNode(): void {
  if (!fs.existsSync(pidFile)) {
    console.log(JSON.stringify({ status: "not_running" }));
    return;
  }
  const pid = Number(fs.readFileSync(pidFile, "utf8").trim());
  if (Number.isInteger(pid) && pid > 0 && isPidRunning(pid)) {
    process.kill(pid, "SIGTERM");
  }
  fs.unlinkSync(pidFile);
  console.log(JSON.stringify({ status: "stopped", pid }));
}

function withKernel<T>(fn: (k: AtlasKernel) => T): T {
  const k = new AtlasKernel(dataDir);
  try {
    return fn(k);
  } finally {
    k.close();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] ?? "help";
  const sub = args[1] ?? "";

  if (cmd === "start") {
    await startNode();
    return;
  }
  if (cmd === "stop") {
    stopNode();
    return;
  }
  if (cmd === "restart") {
    stopNode();
    await new Promise((r) => setTimeout(r, 300));
    await startNode();
    return;
  }
  if (cmd === "status") {
    withKernel((k) => {
      console.log(JSON.stringify(k.status(), null, 2));
    });
    return;
  }
  if (cmd === "health") {
    const port = Number(process.env.PORT) || 3000;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      const data = await res.json();
      console.log(JSON.stringify({ http_ok: res.ok, ...data }, null, 2));
    } catch {
      withKernel((k) => {
        const s = k.status();
        console.log(JSON.stringify({ http_ok: false, offline_db_integrity_ok: s.db_integrity_ok, replay_verified: s.replay_verified }, null, 2));
      });
    }
    return;
  }

  if (cmd === "region") {
    if (sub === "create") {
      const creator = argFlag(args, "--creator");
      const name = argFlag(args, "--name") ?? "ATLAS";
      const prefix = argFlag(args, "--prefix") ?? "ATL";
      const title = argFlag(args, "--title") ?? "Atlas Vector Region";
      const visibility = argFlag(args, "--visibility") === "private" ? "private" : "public";
      const section = Number(argFlag(args, "--section") ?? "1");
      const accessKey = argFlag(args, "--access-key") ?? null;
      if (!creator) throw new Error("--creator <wallet_id> is required");
      withKernel((k) => {
        const res = k.createSignedRegionWithWallet({
          creatorWalletId: creator,
          regionName: name,
          regionPrefix: prefix,
          suggestedTitle: title,
          visibility,
          section,
          accessKey,
        });
        console.log(JSON.stringify(res.region, null, 2));
      });
      return;
    }
    if (sub === "info") {
      const idOrName = args[2] ?? "ATLAS";
      withKernel((k) => {
        const region = k.getRegion(idOrName);
        if (!region) throw new Error(`region not found: ${idOrName}`);
        console.log(JSON.stringify(region, null, 2));
      });
      return;
    }
    if (sub === "list") {
      withKernel((k) => {
        console.log(JSON.stringify(k.listRegions(), null, 2));
      });
      return;
    }
  }

  if (cmd === "wallet") {
    if (sub === "create") {
      const label = argFlag(args, "--label") ?? args[2] ?? "wallet";
      const regionId = argFlag(args, "--region") ?? null;
      const creatorWalletId = argFlag(args, "--creator") ?? null;
      withKernel((k) => {
        const resolvedRegion = regionId ? k.getRegion(regionId)?.region_id ?? regionId : null;
        const created = k.createOpenWallet(label, resolvedRegion, creatorWalletId);
        console.log(JSON.stringify(created, null, 2));
      });
      return;
    }
    if (sub === "info") {
      const id = args[2];
      if (!id) throw new Error("wallet id or public key is required");
      withKernel((k) => {
        const w = k.getWallet(id);
        if (!w) throw new Error(`wallet not found: ${id}`);
        console.log(JSON.stringify({ ...w, auth_ratio: k.computeWalletAuthRatio(w) }, null, 2));
      });
      return;
    }
    if (sub === "balance") {
      const id = args[2];
      if (!id) throw new Error("wallet id is required");
      withKernel((k) => {
        const w = k.getWallet(id);
        if (!w) throw new Error(`wallet not found: ${id}`);
        const balances = k.store.listTokenBalancesForWallet(w.wallet_id).map((b) => {
          const token = k.store.getToken(b.token_id);
          return {
            ...b,
            symbol: token?.symbol ?? "UNKNOWN",
            formatted: token ? formatTokenUnits(b.balance, token.decimals) : b.balance,
          };
        });
        console.log(JSON.stringify({ wallet_id: w.wallet_id, balances }, null, 2));
      });
      return;
    }
    if (sub === "transactions") {
      const id = args[2];
      if (!id) throw new Error("wallet id is required");
      withKernel((k) => {
        console.log(JSON.stringify(k.getWalletTransactions(id), null, 2));
      });
      return;
    }
  }

  if (cmd === "token") {
    if (sub === "create") {
      const authority = argFlag(args, "--authority");
      const name = argFlag(args, "--name") ?? "ATLAS TOKEN";
      const symbol = argFlag(args, "--symbol") ?? "ATLAS";
      const region = argFlag(args, "--region") ?? "ATLAS";
      const decimals = Number(argFlag(args, "--decimals") ?? "8");
      const maxSupply = argFlag(args, "--max-supply") ?? "100000000000000000";
      const policy = argFlag(args, "--policy") ?? "bounded-reserve-transport-supply";
      const drainBps = argFlag(args, "--drain-bps");
      if (!authority) throw new Error("--authority <wallet_id> is required");
      withKernel((k) => {
        const reg = k.getRegion(region);
        if (!reg) throw new Error(`region not found: ${region}`);
        const res = k.createTokenWithWallet({
          authorityWalletId: authority,
          requestId: `tkn_create_${Date.now()}`,
          name,
          symbol,
          regionId: reg.region_id,
          decimals,
          maxSupply,
          supplyPolicy: policy,
          drainBps: drainBps !== undefined ? Number(drainBps) : undefined,
        });
        console.log(JSON.stringify(res.token, null, 2));
      });
      return;
    }
    if (sub === "info") {
      const idOrSym = args[2] ?? "ATLAS";
      withKernel((k) => {
        const token = k.store.getToken(idOrSym);
        if (!token) throw new Error(`token not found: ${idOrSym}`);
        console.log(
          JSON.stringify(
            {
              token,
              conservation: k.verifySupplyConservation(token.token_id),
              balances: k.store.listTokenBalancesForToken(token.token_id),
            },
            null,
            2,
          ),
        );
      });
      return;
    }
    if (sub === "transport") {
      const authority = argFlag(args, "--authority");
      const tokenArg = argFlag(args, "--token") ?? "ATLAS";
      const to = argFlag(args, "--to");
      const amount = argFlag(args, "--amount");
      if (!authority || !to || !amount) throw new Error("--authority, --to, and --amount are required");
      withKernel((k) => {
        const token = k.store.getToken(tokenArg);
        if (!token) throw new Error(`token not found: ${tokenArg}`);
        const res = k.transportTokenWithWallet({
          authorityWalletId: authority,
          requestId: argFlag(args, "--request-id") ?? `transport_${Date.now()}`,
          tokenId: token.token_id,
          toWalletId: to,
          amount,
        });
        console.log(JSON.stringify({ token: res.token, balance: res.balance, event_hash: res.event.event_hash }, null, 2));
      });
      return;
    }
    if (sub === "burn") {
      const from = argFlag(args, "--from");
      const tokenArg = argFlag(args, "--token") ?? "ATLAS";
      const amount = argFlag(args, "--amount");
      if (!from || !amount) throw new Error("--from and --amount are required");
      withKernel((k) => {
        const token = k.store.getToken(tokenArg);
        if (!token) throw new Error(`token not found: ${tokenArg}`);
        const res = k.burnTokenWithWallet({
          ownerWalletId: from,
          requestId: argFlag(args, "--request-id") ?? `burn_${Date.now()}`,
          tokenId: token.token_id,
          amount,
        });
        console.log(JSON.stringify({ token: res.token, balance: res.balance, event_hash: res.event.event_hash }, null, 2));
      });
      return;
    }
  }

  if (cmd === "transfer") {
    const from = argFlag(args, "--from");
    const to = argFlag(args, "--to");
    const tokenArg = argFlag(args, "--token") ?? "ATLAS";
    const amount = argFlag(args, "--amount");
    if (!from || !to || !amount) throw new Error("--from, --to, and --amount are required");
    withKernel((k) => {
      const token = k.store.getToken(tokenArg);
      if (!token) throw new Error(`token not found: ${tokenArg}`);
      const res = k.transferTokenWithWallet({
        senderWalletId: from,
        requestId: argFlag(args, "--request-id") ?? `tx_${Date.now()}`,
        tokenId: token.token_id,
        toWalletId: to,
        amount,
      });
      console.log(
        JSON.stringify(
          {
            record_id: res.record.recordId,
            event_hash: res.event.event_hash,
            from_balance: res.fromBalance,
            to_balance: res.toBalance,
            drain: res.drain,
            rewards: res.rewards,
          },
          null,
          2,
        ),
      );
    });
    return;
  }

  if (cmd === "transaction" && sub === "inspect") {
    const id = args[2];
    if (!id) throw new Error("transaction/record/event id is required");
    withKernel((k) => {
      const record =
        k.store.getRecord(id) ??
        k.store.listRecords().find((r) => (r.parameters as Record<string, unknown>)?.request_id === id) ??
        null;
      const event = k.store.getEventByHash(id) ?? k.store.getEventById(id);
      console.log(JSON.stringify({ record, event }, null, 2));
    });
    return;
  }

  if (cmd === "history" && sub === "replay") {
    withKernel((k) => {
      console.log(JSON.stringify(k.replayCanonicalHistory(), null, 2));
    });
    return;
  }

  if (cmd === "backup") {
    const dest = argFlag(args, "--out") ?? path.join(dataDir, "backups", `atlas-backup-${Date.now()}.db`);
    withKernel((k) => {
      k.store.backupTo(dest);
      console.log(JSON.stringify({ ok: true, backup_path: dest }));
    });
    return;
  }

  console.log(`atlas CLI for v-kernelx
Commands:
  atlas start | stop | restart | status | health
  atlas region create --creator <wallet_id> [--name ATLAS --prefix ATL --title "Atlas Vector Region" --visibility public --section 1]
  atlas region info [ATLAS]
  atlas region list
  atlas wallet create --label <name> [--region <region_id> --creator <wallet_id>]
  atlas wallet info <wallet_id>
  atlas wallet balance <wallet_id>
  atlas wallet transactions <wallet_id>
  atlas token create --authority <wallet_id> [--name "ATLAS TOKEN" --symbol ATLAS --region ATLAS --decimals 8 --max-supply 100000000000000000 --drain-bps 200]
  atlas token info [ATLAS]
  atlas token transport --authority <wallet_id> --token ATLAS --to <wallet_id> --amount <atomic_u128>
  atlas token burn --from <wallet_id> --token ATLAS --amount <atomic_u128>
  atlas transfer --from <wallet_id> --to <wallet_id> --token ATLAS --amount <atomic_u128>
  atlas transaction inspect <record_id|event_hash|request_id>
  atlas history replay
  atlas backup [--out <path>]`);
}

main().catch((err) => {
  console.error(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
  process.exit(1);
});
