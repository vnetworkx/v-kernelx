export type VerificationStatus =
  | "VERIFIED"
  | "UNVERIFIED"
  | "INVALID"
  | "UNAVAILABLE";

export type TransferScopeDto =
  | "SAME_WALLET"
  | "DIFFERENT_WALLETS_SAME_REGION"
  | "DIFFERENT_REGIONS_SAME_SPACE"
  | "DIFFERENT_SPACES";

export type ScopeDrainRateDto =
  | { status: "UNCONFIGURED" }
  | { status: "CONFIGURED_BPS"; bps: number };

export interface DrainPolicyDto {
  policy_version: number;
  same_wallet: ScopeDrainRateDto;
  different_wallets_same_region: ScopeDrainRateDto;
  different_regions_same_space: ScopeDrainRateDto;
  different_spaces: ScopeDrainRateDto;
}

export interface StateRootDto {
  root_hash: string;
  event_count: number;
  logical_clock: number;
}

export interface NodeStatusDto {
  kernel_version: string;
  protocol_version?: string;
  network_name: string;
  network_mode: string;
  node_id: string;
  node_pubkey: string;
  storage_engine: string;
  db_path: string;
  db_integrity_ok: boolean;
  wal_consistency_ok: boolean;
  equivocation_store_ok: boolean;
  equivocation_count: number;
  verification_status: VerificationStatus;
  replay_status: VerificationStatus;
  key_storage_mode?: string;
  vector_count: number;
  record_count: number;
  event_count: number;
  region_count: number;
  wallet_count: number;
  token_count: number;
  validator_count: number;
  certificate_count?: number;
  finalized_event_count: number;
  total_drain_rewards_count: number;
  state_root: StateRootDto;
  replay_hash: string;
  replay_verified: boolean;
}

export interface SpaceDto {
  space_id: string;
  name: string;
  visibility: "public" | "private";
  ghost: boolean;
  owner_pubkey: string;
  created_at_ms: number;
  version: number;
  metadata: Record<string, string>;
}

export interface RegionDto {
  region_id: string;
  space_id?: string | null;
  region_root: string;
  region_name: string;
  normalized_name: string;
  region_prefix: string | null;
  suggested_title: string | null;
  visibility: "public" | "private";
  section: number | null;
  ghost?: boolean;
  auth_ratio_bps: number | null;
  creator_public_key: string;
  trigger_event_hash: string | null;
  creation_proof_hash: string | null;
  access_key_hash: string | null;
  created_at_ms: number;
  updated_at_ms: number;
  version: number;
  metadata: Record<string, string>;
}

export interface TokenBalanceDto {
  token_id: string;
  wallet_id: string;
  owner_pubkey: string;
  balance: string;
  updated_at_ms: number;
  version: number;
}

export type BeneficiaryRole =
  | "region_creator"
  | "wallet_creator"
  | "token_creator"
  | "network_pool";

export interface DrainRewardDto {
  reward_id: string;
  tx_request_id: string;
  token_id: string | null;
  vector_id: string | null;
  beneficiary_role: BeneficiaryRole;
  wallet_id: string;
  amount: string;
  dimension_amounts?: string[];
  timestamp_ms: number;
}

export interface DrainFeeBreakdownDto {
  base_bps: number;
  effective_bps: number;
  auth_ratio: number;
  threshold: number;
  discounted: boolean;
  total_fee: string;
  net_received: string;
  region_creator_reward: string;
  wallet_creator_reward: string;
  token_creator_reward: string;
  network_reward: string;
}

export interface WalletReceivePolicyDto {
  mode: "OPEN" | "RESTRICTED" | "FROZEN";
  allowed_senders?: string[];
}

export interface WalletDto {
  wallet_id: string;
  public_key_hex: string;
  label: string;
  region_id: string | null;
  space_id?: string | null;
  ghost?: boolean;
  creator_wallet_id: string | null;
  receive_policy?: WalletReceivePolicyDto;
  created_at_ms: number;
  auth_ratio: number | null;
  balances: TokenBalanceDto[];
  rewards: DrainRewardDto[];
}

export interface SupplyConservationDto {
  conserved: boolean;
  verification_status: VerificationStatus;
  verification_reason?: string | null;
  total_supply: string;
  sum_of_balances: string;
  wallet_balances_total?: string;
  escrow_balances_total?: string;
  locked_collateral_total?: string;
  reserve_balances_total?: string;
  ghost_custody_balances_total?: string;
  unknown_account_balances_total?: string;
  burned_supply?: string | null;
  drained_fees_total?: string | null;
  minted_minus_burned: string;
  transported_minus_burned?: string;
}

export interface TokenDto {
  token_id: string;
  name: string;
  symbol: string;
  wallet_id?: string | null;
  region_id: string;
  space_id?: string | null;
  ghost?: boolean;
  decimals: number;
  max_supply: string;
  total_supply: string;
  minted_supply: string;
  transported_supply?: string;
  burned_supply: string | null;
  drained_fees_collected?: string | null;
  drain_bps?: number | null;
  drain_policy?: DrainPolicyDto | null;
  authority_pubkey: string;
  supply_policy: string;
  token_type: string;
  created_at_ms: number;
  updated_at_ms: number;
  version: number;
  balances: TokenBalanceDto[];
  conservation: SupplyConservationDto;
}

export interface ParticipantScopeDto {
  level: string;
  target_id?: string | null;
  granted_by?: string;
  granted_at_ms?: number;
  expires_at_ms?: number | null;
}

export interface ParticipantDto {
  participant_id: string;
  identity_pubkey: string;
  display_name: string;
  created_at_ms: number;
  scopes: ParticipantScopeDto[];
  active: boolean;
}

export interface NodeDto {
  node_id: string;
  operator_pubkey: string;
  listen_addr: string;
  roles: string[];
  region_id: string | null;
  active: boolean;
  joined_at_ms: number;
}

export interface ContractDto {
  contract_id: string;
  name: string;
  space_id: string | null;
  region_id: string | null;
  creator_pubkey: string;
  rules: Record<string, unknown>;
  actions: unknown[];
  execution_count: number;
  active: boolean;
  state_data?: Record<string, unknown>;
  escrow_balances?: Record<string, string | number>;
  created_at_ms: number;
  version: number;
}

export interface LoanDto {
  loan_id: string;
  name: string;
  token_id: string;
  lender_wallet_id: string;
  borrower_wallet_id: string;
  principal: string;
  disbursed_amount?: string;
  collateral_locked: string;
  repaid_amount: string;
  accrued_interest?: string;
  interest_bps: number;
  maturity_at_ms?: number | null;
  defaulted?: boolean;
  status: string;
  created_at_ms: number;
  version: number;
}

export interface ProgramDto {
  program_id: string;
  file_name: string;
  actor_pubkey: string;
  status: string;
  source_hash: string;
  compiled_program_hash?: string | null;
  resulting_event_ids: string[];
  created_entities: string[];
  outputs: string[];
  error_message?: string | null;
  submitted_at_ms: number;
}

export interface GhostAssessmentDto {
  network_id: string;
  total_ghost_entities: number;
  ghost_spaces: string[];
  ghost_regions: string[];
  parentless_regions: string[];
  ghost_wallets: string[];
  parentless_wallets: string[];
  ghost_tokens: string[];
  parentless_tokens: string[];
  risk_flags: string[];
  ghost_ledger_commitment: string;
}

export interface GhostEntitiesDto {
  spaces: SpaceDto[];
  regions: Array<Record<string, unknown>>;
  wallets: Array<Record<string, unknown>>;
  tokens: Array<Record<string, unknown>>;
  assessment: GhostAssessmentDto | null;
}

export interface HierarchyCommitmentsDto {
  network_commitment: string;
  ghost_commitment: string;
  space_commitments: Record<string, string>;
  region_commitments: Record<string, string>;
  wallet_commitments: Record<string, string>;
  token_commitments: Record<string, string>;
}

export interface ProjectionStateDto {
  escrowId: string;
  projectedComponents: number[];
  settledComponents: number[];
  startedAtMs: number;
  settlementAtMs?: number | null;
  outcomeTag?: string | null;
}

export interface OriginMetadataDto {
  seed: string;
  nonce: number;
  difficulty: number;
  proofHash: string;
}

export interface VectorStateDto {
  schema: string;
  vectorId: string;
  ownerPubkey: string;
  spaceId: string;
  vectorType: string;
  status: string;
  components: number[];
  typeMetadata: Record<string, string>;
  certification: {
    certified: boolean;
    authRatio: number;
    threshold: number;
    lastCheckedAtMs: number;
    reason?: string | null;
  };
  projection?: ProjectionStateDto | null;
  origin?: OriginMetadataDto | null;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface VectorRecordDto {
  schema: string;
  recordId: string;
  vectorId: string;
  before?: VectorStateDto | null;
  after: VectorStateDto;
  operation: string;
  parameters?: unknown;
  certification: VectorStateDto["certification"];
  timestampMs: number;
  proof: string;
}

export interface CanonicalEventDto {
  event_id: string;
  parent_hashes: string[];
  entity_kind?: string;
  region_id: string;
  entity_id: string;
  operation: { type: string; value?: string };
  vector_before: {
    components: string[];
    owner_public_key: string;
    type_tag: string;
    metadata: Record<string, string>;
  };
  vector_after: {
    components: string[];
    owner_public_key: string;
    type_tag: string;
    metadata: Record<string, string>;
  };
  auth_ratio: number | null;
  certified: boolean;
  verification_status?: VerificationStatus;
  actor_public_key: string;
  logical_clock: number;
  timestamp: number;
  payload_hash: string;
  event_hash: string;
  signature: string | null;
}

export interface SnapshotDto {
  snapshot_id: string;
  state_root: StateRootDto;
  event_root: string | null;
  proposal_digest?: string;
  verification_status?: VerificationStatus;
  replay_hash: string;
  event_count: number;
  logical_clock: number;
  dag_heads: string[];
  created_at: number;
}

export interface ReplayDto {
  state_root: StateRootDto;
  replay_hash: string;
  applied_event_hashes: string[];
  matches_stored_state: boolean;
  verification_status?: VerificationStatus;
  events_replayed?: number;
  replayed_state_root?: string;
  live_state_root?: string;
  mismatch_reasons: string[];
}

export interface ValidatorNodeDto {
  node_id: string;
  public_key_hex: string;
  label: string;
  weight: number;
  active: boolean;
  joined_at_ms: number;
}

export interface EventAttestationDto {
  event_hash: string;
  validator_id: string;
  validator_pubkey: string;
  vote_accept: boolean;
  state_root_hash: string;
  signature: string;
  timestamp_ms: number;
}

export interface ConsensusRoundDto {
  event_hash: string;
  total_weight: number;
  approving_weight: number;
  quorum_threshold_bps: number;
  finalized: boolean;
  attestations: EventAttestationDto[];
}

export interface BrowserSignerKey {
  wallet_id: string;
  public_key_hex: string;
  private_key_hex: string;
  label: string;
}

export interface SyncBundle {
  protocol: string;
  source_node_id: string;
  source_node_pubkey: string;
  exported_at_ms: number;
  state_root: StateRootDto;
  replay_hash: string;
  validators: ValidatorNodeDto[];
  events: unknown[];
  attestations: EventAttestationDto[];
}
