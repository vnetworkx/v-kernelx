import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { VectorRecordV1, VectorStateV1 } from "./types.ts";
import type { CanonicalSnapshot, CanonicalVectorEvent } from "./serialization.ts";
import type { RegionState } from "./region.ts";
import type { DrainRewardRecord, TokenBalance, TokenDefinition } from "./token.ts";
import type { EventAttestation, ValidatorNode } from "./vectors.ts";

export interface PublicWalletRecord {
  wallet_id: string;
  public_key_hex: string;
  label: string;
  region_id: string | null;
  creator_wallet_id: string | null;
  created_at_ms: number;
}

export class SqliteKernelStore {
  readonly dbPath: string;
  private db: DatabaseSync;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;

      CREATE TABLE IF NOT EXISTS node_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS vectors (
        vector_id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS records (
        record_id TEXT PRIMARY KEY,
        vector_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        data_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS events (
        event_hash TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        entity_id TEXT NOT NULL,
        region_id TEXT NOT NULL,
        logical_clock INTEGER NOT NULL,
        timestamp INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        data_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS regions (
        region_id TEXT PRIMARY KEY,
        lookup_key TEXT NOT NULL UNIQUE,
        region_name TEXT NOT NULL,
        region_prefix TEXT,
        data_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS wallets (
        wallet_id TEXT PRIMARY KEY,
        public_key_hex TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        region_id TEXT,
        creator_wallet_id TEXT,
        created_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS tokens (
        token_id TEXT PRIMARY KEY,
        region_id TEXT NOT NULL,
        symbol TEXT NOT NULL,
        data_json TEXT NOT NULL,
        UNIQUE(region_id, symbol)
      );

      CREATE TABLE IF NOT EXISTS token_balances (
        token_id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        owner_pubkey TEXT NOT NULL,
        balance TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        version INTEGER NOT NULL,
        PRIMARY KEY (token_id, wallet_id)
      );

      CREATE TABLE IF NOT EXISTS drain_rewards (
        reward_id TEXT PRIMARY KEY,
        tx_request_id TEXT NOT NULL,
        token_id TEXT,
        vector_id TEXT,
        beneficiary_role TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        amount TEXT NOT NULL,
        dimension_amounts_json TEXT,
        timestamp_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS consensus_validators (
        node_id TEXT PRIMARY KEY,
        public_key_hex TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        weight INTEGER NOT NULL,
        active INTEGER NOT NULL,
        joined_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS event_attestations (
        event_hash TEXT NOT NULL,
        validator_id TEXT NOT NULL,
        validator_pubkey TEXT NOT NULL,
        vote_accept INTEGER NOT NULL,
        state_root_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        PRIMARY KEY (event_hash, validator_id)
      );

      CREATE TABLE IF NOT EXISTS seen_requests (
        request_id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS snapshots (
        snapshot_id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
      );
    `);

    // Idempotent column migration for existing pre-upgrade SQLite databases
    const walletCols = this.db.prepare("PRAGMA table_info(wallets)").all() as Array<{ name: string }>;
    if (!walletCols.some((c) => c.name === "creator_wallet_id")) {
      this.db.exec("ALTER TABLE wallets ADD COLUMN creator_wallet_id TEXT");
    }
  }

  close(): void {
    this.db.close();
  }

  inTransaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // ignore rollback error if already aborted
      }
      throw err;
    }
  }

  integrityCheck(): boolean {
    const row = this.db.prepare("PRAGMA integrity_check").get() as { integrity_check?: string } | undefined;
    return row?.integrity_check === "ok";
  }

  backupTo(destPath: string): void {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    if (fs.existsSync(destPath)) {
      fs.unlinkSync(destPath);
    }
    const escaped = destPath.replace(/'/g, "''");
    this.db.exec(`VACUUM INTO '${escaped}'`);
  }

  getMeta(key: string): string | null {
    const row = this.db.prepare("SELECT value FROM node_meta WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row ? row.value : null;
  }

  setMeta(key: string, value: string): void {
    this.db
      .prepare(
        "INSERT INTO node_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      )
      .run(key, value);
  }

  hasSeenRequest(requestId: string): boolean {
    const row = this.db
      .prepare("SELECT 1 AS found FROM seen_requests WHERE request_id = ?")
      .get(requestId);
    return Boolean(row);
  }

  markRequestSeen(requestId: string, operation: string, createdAtMs: number): void {
    this.db
      .prepare("INSERT INTO seen_requests (request_id, operation, created_at_ms) VALUES (?, ?, ?)")
      .run(requestId, operation, createdAtMs);
  }

  putVector(state: VectorStateV1): void {
    this.db
      .prepare(
        `INSERT INTO vectors (vector_id, data_json, updated_at_ms)
         VALUES (?, ?, ?)
         ON CONFLICT(vector_id) DO UPDATE SET data_json = excluded.data_json, updated_at_ms = excluded.updated_at_ms`,
      )
      .run(state.vectorId, JSON.stringify(state), state.updatedAtMs);
  }

  getVector(vectorId: string): VectorStateV1 | null {
    const row = this.db
      .prepare("SELECT data_json FROM vectors WHERE vector_id = ?")
      .get(vectorId) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as VectorStateV1) : null;
  }

  listVectors(): VectorStateV1[] {
    const rows = this.db
      .prepare("SELECT data_json FROM vectors ORDER BY vector_id ASC")
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as VectorStateV1);
  }

  private nextRecordSeq(): number {
    const row = this.db.prepare("SELECT COALESCE(MAX(seq), 0) AS m FROM records").get() as {
      m: number;
    };
    return Number(row.m) + 1;
  }

  putRecord(record: VectorRecordV1): void {
    const seq = this.nextRecordSeq();
    this.db
      .prepare(
        `INSERT INTO records (record_id, vector_id, operation, timestamp_ms, seq, data_json)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(record_id) DO UPDATE SET data_json = excluded.data_json`,
      )
      .run(
        record.recordId,
        record.vectorId,
        record.operation,
        record.timestampMs,
        seq,
        JSON.stringify(record),
      );
  }

  getRecord(recordId: string): VectorRecordV1 | null {
    const row = this.db
      .prepare("SELECT data_json FROM records WHERE record_id = ?")
      .get(recordId) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as VectorRecordV1) : null;
  }

  listRecords(): VectorRecordV1[] {
    const rows = this.db
      .prepare("SELECT data_json FROM records ORDER BY seq ASC")
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as VectorRecordV1);
  }

  private nextEventSeq(): number {
    const row = this.db.prepare("SELECT COALESCE(MAX(seq), 0) AS m FROM events").get() as {
      m: number;
    };
    return Number(row.m) + 1;
  }

  appendEvent(event: CanonicalVectorEvent): void {
    if (!event.event_id) {
      throw new Error("attempted to append event with empty event_id");
    }
    if (!event.event_hash) {
      throw new Error("attempted to append event with empty event_hash");
    }
    const existingByHash = this.getEventByHash(event.event_hash);
    if (existingByHash) {
      throw new Error(`duplicate canonical event_hash detected: ${event.event_hash}`);
    }
    const existingById = this.getEventById(event.event_id);
    if (existingById) {
      throw new Error(`duplicate event_id detected: ${event.event_id}`);
    }
    const seq = this.nextEventSeq();
    this.db
      .prepare(
        `INSERT INTO events (event_hash, event_id, entity_id, region_id, logical_clock, timestamp, seq, data_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.event_hash,
        event.event_id,
        event.entity_id,
        event.region_id,
        event.logical_clock,
        event.timestamp,
        seq,
        JSON.stringify(event),
      );
  }

  getEventByHash(eventHash: string): CanonicalVectorEvent | null {
    const row = this.db
      .prepare("SELECT data_json FROM events WHERE event_hash = ?")
      .get(eventHash) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as CanonicalVectorEvent) : null;
  }

  getEventById(eventId: string): CanonicalVectorEvent | null {
    const row = this.db
      .prepare("SELECT data_json FROM events WHERE event_id = ?")
      .get(eventId) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as CanonicalVectorEvent) : null;
  }

  listEvents(): CanonicalVectorEvent[] {
    const rows = this.db
      .prepare(
        "SELECT data_json FROM events ORDER BY logical_clock ASC, timestamp ASC, event_hash ASC, event_id ASC",
      )
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as CanonicalVectorEvent);
  }

  putRegion(region: RegionState, lookupKey: string): void {
    this.db
      .prepare(
        `INSERT INTO regions (region_id, lookup_key, region_name, region_prefix, data_json)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        region.region_id,
        lookupKey,
        region.region_name,
        region.region_prefix,
        JSON.stringify(region),
      );
  }

  getRegion(regionId: string): RegionState | null {
    const row = this.db
      .prepare("SELECT data_json FROM regions WHERE region_id = ?")
      .get(regionId) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as RegionState) : null;
  }

  getRegionByLookupKey(lookupKey: string): RegionState | null {
    const row = this.db
      .prepare("SELECT data_json FROM regions WHERE lookup_key = ?")
      .get(lookupKey) as { data_json: string } | undefined;
    return row ? (JSON.parse(row.data_json) as RegionState) : null;
  }

  listRegions(): RegionState[] {
    const rows = this.db
      .prepare("SELECT data_json FROM regions ORDER BY region_name ASC, region_id ASC")
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as RegionState);
  }

  putWallet(wallet: PublicWalletRecord): void {
    this.db
      .prepare(
        `INSERT INTO wallets (wallet_id, public_key_hex, label, region_id, creator_wallet_id, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        wallet.wallet_id,
        wallet.public_key_hex,
        wallet.label,
        wallet.region_id,
        wallet.creator_wallet_id ?? null,
        wallet.created_at_ms,
      );
  }

  getWallet(walletIdOrPubkey: string): PublicWalletRecord | null {
    const row = this.db
      .prepare(
        "SELECT wallet_id, public_key_hex, label, region_id, creator_wallet_id, created_at_ms FROM wallets WHERE wallet_id = ? OR public_key_hex = ?",
      )
      .get(walletIdOrPubkey, walletIdOrPubkey) as PublicWalletRecord | undefined;
    return row ? { ...row, creator_wallet_id: row.creator_wallet_id ?? null } : null;
  }

  listWallets(): PublicWalletRecord[] {
    const rows = this.db
      .prepare(
        "SELECT wallet_id, public_key_hex, label, region_id, creator_wallet_id, created_at_ms FROM wallets ORDER BY created_at_ms ASC, wallet_id ASC",
      )
      .all() as unknown as PublicWalletRecord[];
    return rows.map((r) => ({ ...r, creator_wallet_id: r.creator_wallet_id ?? null }));
  }

  putToken(token: TokenDefinition): void {
    this.db
      .prepare(
        `INSERT INTO tokens (token_id, region_id, symbol, data_json)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(token_id) DO UPDATE SET data_json = excluded.data_json`,
      )
      .run(token.token_id, token.region_id, token.symbol.toUpperCase(), JSON.stringify(token));
  }

  getToken(tokenIdOrSymbol: string): TokenDefinition | null {
    const byId = this.db
      .prepare("SELECT data_json FROM tokens WHERE token_id = ?")
      .get(tokenIdOrSymbol) as { data_json: string } | undefined;
    if (byId) return JSON.parse(byId.data_json) as TokenDefinition;

    const bySym = this.db
      .prepare("SELECT data_json FROM tokens WHERE UPPER(symbol) = UPPER(?)")
      .get(tokenIdOrSymbol) as { data_json: string } | undefined;
    return bySym ? (JSON.parse(bySym.data_json) as TokenDefinition) : null;
  }

  listTokens(): TokenDefinition[] {
    const rows = this.db
      .prepare("SELECT data_json FROM tokens ORDER BY symbol ASC, token_id ASC")
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as TokenDefinition);
  }

  putTokenBalance(balance: TokenBalance): void {
    this.db
      .prepare(
        `INSERT INTO token_balances (token_id, wallet_id, owner_pubkey, balance, updated_at_ms, version)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(token_id, wallet_id) DO UPDATE SET
           balance = excluded.balance,
           updated_at_ms = excluded.updated_at_ms,
           version = excluded.version`,
      )
      .run(
        balance.token_id,
        balance.wallet_id,
        balance.owner_pubkey,
        balance.balance,
        balance.updated_at_ms,
        balance.version,
      );
  }

  getTokenBalance(tokenId: string, walletId: string): TokenBalance | null {
    const row = this.db
      .prepare(
        "SELECT token_id, wallet_id, owner_pubkey, balance, updated_at_ms, version FROM token_balances WHERE token_id = ? AND wallet_id = ?",
      )
      .get(tokenId, walletId) as TokenBalance | undefined;
    return row ? { ...row } : null;
  }

  listTokenBalancesForToken(tokenId: string): TokenBalance[] {
    const rows = this.db
      .prepare(
        "SELECT token_id, wallet_id, owner_pubkey, balance, updated_at_ms, version FROM token_balances WHERE token_id = ? ORDER BY wallet_id ASC",
      )
      .all(tokenId) as unknown as TokenBalance[];
    return rows.map((r) => ({ ...r }));
  }

  listTokenBalancesForWallet(walletId: string): TokenBalance[] {
    const rows = this.db
      .prepare(
        "SELECT token_id, wallet_id, owner_pubkey, balance, updated_at_ms, version FROM token_balances WHERE wallet_id = ? ORDER BY token_id ASC",
      )
      .all(walletId) as unknown as TokenBalance[];
    return rows.map((r) => ({ ...r }));
  }

  putDrainReward(reward: DrainRewardRecord): void {
    this.db
      .prepare(
        `INSERT INTO drain_rewards (reward_id, tx_request_id, token_id, vector_id, beneficiary_role, wallet_id, amount, dimension_amounts_json, timestamp_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(reward_id) DO NOTHING`,
      )
      .run(
        reward.reward_id,
        reward.tx_request_id,
        reward.token_id,
        reward.vector_id,
        reward.beneficiary_role,
        reward.wallet_id,
        reward.amount,
        reward.dimension_amounts ? JSON.stringify(reward.dimension_amounts) : null,
        reward.timestamp_ms,
      );
  }

  listDrainRewards(limit = 200): DrainRewardRecord[] {
    const rows = this.db
      .prepare(
        "SELECT reward_id, tx_request_id, token_id, vector_id, beneficiary_role, wallet_id, amount, dimension_amounts_json, timestamp_ms FROM drain_rewards ORDER BY timestamp_ms DESC, reward_id ASC LIMIT ?",
      )
      .all(limit) as Array<{
      reward_id: string;
      tx_request_id: string;
      token_id: string | null;
      vector_id: string | null;
      beneficiary_role: DrainRewardRecord["beneficiary_role"];
      wallet_id: string;
      amount: string;
      dimension_amounts_json: string | null;
      timestamp_ms: number;
    }>;
    return rows.map((r) => ({
      reward_id: r.reward_id,
      tx_request_id: r.tx_request_id,
      token_id: r.token_id,
      vector_id: r.vector_id,
      beneficiary_role: r.beneficiary_role,
      wallet_id: r.wallet_id,
      amount: r.amount,
      dimension_amounts: r.dimension_amounts_json
        ? (JSON.parse(r.dimension_amounts_json) as string[])
        : undefined,
      timestamp_ms: Number(r.timestamp_ms),
    }));
  }

  listDrainRewardsForWallet(walletId: string): DrainRewardRecord[] {
    const rows = this.db
      .prepare(
        "SELECT reward_id, tx_request_id, token_id, vector_id, beneficiary_role, wallet_id, amount, dimension_amounts_json, timestamp_ms FROM drain_rewards WHERE wallet_id = ? ORDER BY timestamp_ms DESC",
      )
      .all(walletId) as Array<{
      reward_id: string;
      tx_request_id: string;
      token_id: string | null;
      vector_id: string | null;
      beneficiary_role: DrainRewardRecord["beneficiary_role"];
      wallet_id: string;
      amount: string;
      dimension_amounts_json: string | null;
      timestamp_ms: number;
    }>;
    return rows.map((r) => ({
      reward_id: r.reward_id,
      tx_request_id: r.tx_request_id,
      token_id: r.token_id,
      vector_id: r.vector_id,
      beneficiary_role: r.beneficiary_role,
      wallet_id: r.wallet_id,
      amount: r.amount,
      dimension_amounts: r.dimension_amounts_json
        ? (JSON.parse(r.dimension_amounts_json) as string[])
        : undefined,
      timestamp_ms: Number(r.timestamp_ms),
    }));
  }

  putValidator(validator: ValidatorNode): void {
    this.db
      .prepare(
        `INSERT INTO consensus_validators (node_id, public_key_hex, label, weight, active, joined_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(node_id) DO UPDATE SET
           public_key_hex = excluded.public_key_hex,
           label = excluded.label,
           weight = excluded.weight,
           active = excluded.active`,
      )
      .run(
        validator.node_id,
        validator.public_key_hex,
        validator.label,
        validator.weight,
        validator.active ? 1 : 0,
        validator.joined_at_ms,
      );
  }

  getValidator(nodeId: string): ValidatorNode | null {
    const row = this.db
      .prepare(
        "SELECT node_id, public_key_hex, label, weight, active, joined_at_ms FROM consensus_validators WHERE node_id = ?",
      )
      .get(nodeId) as
      | {
          node_id: string;
          public_key_hex: string;
          label: string;
          weight: number;
          active: number;
          joined_at_ms: number;
        }
      | undefined;
    return row
      ? {
          node_id: row.node_id,
          public_key_hex: row.public_key_hex,
          label: row.label,
          weight: Number(row.weight),
          active: Boolean(row.active),
          joined_at_ms: Number(row.joined_at_ms),
        }
      : null;
  }

  listValidators(): ValidatorNode[] {
    const rows = this.db
      .prepare(
        "SELECT node_id, public_key_hex, label, weight, active, joined_at_ms FROM consensus_validators ORDER BY joined_at_ms ASC, node_id ASC",
      )
      .all() as Array<{
      node_id: string;
      public_key_hex: string;
      label: string;
      weight: number;
      active: number;
      joined_at_ms: number;
    }>;
    return rows.map((row) => ({
      node_id: row.node_id,
      public_key_hex: row.public_key_hex,
      label: row.label,
      weight: Number(row.weight),
      active: Boolean(row.active),
      joined_at_ms: Number(row.joined_at_ms),
    }));
  }

  putAttestation(att: EventAttestation): void {
    this.db
      .prepare(
        `INSERT INTO event_attestations (event_hash, validator_id, validator_pubkey, vote_accept, state_root_hash, signature, timestamp_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(event_hash, validator_id) DO UPDATE SET
           vote_accept = excluded.vote_accept,
           state_root_hash = excluded.state_root_hash,
           signature = excluded.signature,
           timestamp_ms = excluded.timestamp_ms`,
      )
      .run(
        att.event_hash,
        att.validator_id,
        att.validator_pubkey,
        att.vote_accept ? 1 : 0,
        att.state_root_hash,
        att.signature,
        att.timestamp_ms,
      );
  }

  listAttestationsForEvent(eventHash: string): EventAttestation[] {
    const rows = this.db
      .prepare(
        "SELECT event_hash, validator_id, validator_pubkey, vote_accept, state_root_hash, signature, timestamp_ms FROM event_attestations WHERE event_hash = ? ORDER BY timestamp_ms ASC",
      )
      .all(eventHash) as Array<{
      event_hash: string;
      validator_id: string;
      validator_pubkey: string;
      vote_accept: number;
      state_root_hash: string;
      signature: string;
      timestamp_ms: number;
    }>;
    return rows.map((r) => ({
      event_hash: r.event_hash,
      validator_id: r.validator_id,
      validator_pubkey: r.validator_pubkey,
      vote_accept: Boolean(r.vote_accept),
      state_root_hash: r.state_root_hash,
      signature: r.signature,
      timestamp_ms: Number(r.timestamp_ms),
    }));
  }

  listAllAttestations(): EventAttestation[] {
    const rows = this.db
      .prepare(
        "SELECT event_hash, validator_id, validator_pubkey, vote_accept, state_root_hash, signature, timestamp_ms FROM event_attestations ORDER BY timestamp_ms ASC",
      )
      .all() as Array<{
      event_hash: string;
      validator_id: string;
      validator_pubkey: string;
      vote_accept: number;
      state_root_hash: string;
      signature: string;
      timestamp_ms: number;
    }>;
    return rows.map((r) => ({
      event_hash: r.event_hash,
      validator_id: r.validator_id,
      validator_pubkey: r.validator_pubkey,
      vote_accept: Boolean(r.vote_accept),
      state_root_hash: r.state_root_hash,
      signature: r.signature,
      timestamp_ms: Number(r.timestamp_ms),
    }));
  }

  putSnapshot(snapshot: CanonicalSnapshot): void {
    this.db
      .prepare(
        `INSERT INTO snapshots (snapshot_id, created_at, data_json)
         VALUES (?, ?, ?)
         ON CONFLICT(snapshot_id) DO UPDATE SET data_json = excluded.data_json`,
      )
      .run(snapshot.snapshot_id, snapshot.created_at, JSON.stringify(snapshot));
  }

  listSnapshots(): CanonicalSnapshot[] {
    const rows = this.db
      .prepare("SELECT data_json FROM snapshots ORDER BY created_at DESC")
      .all() as Array<{ data_json: string }>;
    return rows.map((r) => JSON.parse(r.data_json) as CanonicalSnapshot);
  }
}
