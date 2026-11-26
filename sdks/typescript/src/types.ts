export type ParticipationLevel = "NETWORK" | "SPACE" | "REGION" | "WALLET" | "TOKEN";

export type NetworkProfile = "DEVELOPMENT" | "TESTNET" | "PRODUCTION";

export type ProgramLifecycleStatus =
  | "RECEIVED"
  | "PARSING"
  | "COMPILED"
  | "VALIDATING"
  | "AWAITING_AUTHORIZATION"
  | "AWAITING_CONSENSUS"
  | "COMMITTED"
  | "REJECTED"
  | "FAILED";

export interface KeypairMaterial {
  key_role: string;
  derived_id: string;
  public_key_hex: string;
  private_key_hex: string;
}

export interface NetworkInfo {
  network_id: string;
  network_name: string;
  profile: NetworkProfile;
  protocol_version: string;
  node_id: string;
  peer_id: string;
  listen_addresses: string[];
  advertised_addresses: string[];
  bootstrap_peers: string[];
  height: number;
  state_root: string;
  quorum_threshold_bps: number;
  validator_count: number;
  allow_bootstrap_atlas: boolean;
}

export interface NetworkStatus {
  network_id: string;
  profile: NetworkProfile;
  node_id: string;
  peer_id: string;
  height: number;
  logical_clock: number;
  committed_events: number;
  certificates: number;
  connected_peers: number;
  participants: number;
  spaces: number;
  regions: number;
  wallets: number;
  tokens: number;
  contracts: number;
  loans: number;
  programs: number;
  active_validators: number;
  required_quorum_weight: number;
  total_validator_weight: number;
  state_root: string;
  replay_hash: string;
}

export interface CreatedEntitySummary {
  kind: string;
  id: string;
  name: string;
}

export interface QuorumCertificate {
  certificate_id: string;
  network_id: string;
  proposal_id: string;
  height: number;
  epoch: number;
  validator_set_hash?: string;
  state_root: string;
  event_root: string;
  approved_weight: number;
  total_weight: number;
  quorum_threshold_bps: number;
  signatures: Array<{
    validator_id: string;
    validator_pubkey_hex: string;
    signature: string;
  }>;
  finalized_at_ms: number;
}

export interface ProgramSubmission {
  program_id: string;
  file_name: string;
  file_kind: string;
  source_hash: string;
  language_version: string;
  compiler_version: string;
  compiled_program_hash: string;
  protocol_version: string;
  network_id: string;
  submitter_participant_id: string;
  submitter_pubkey: string;
  request_id: string;
  nonce: number;
  status: ProgramLifecycleStatus;
  failed_operation_index?: number | null;
  error_message?: string | null;
  resulting_event_ids: string[];
  consensus_certificate?: QuorumCertificate | null;
  final_state_root?: string | null;
  created_entities: CreatedEntitySummary[];
  outputs: string[];
  submitted_at_ms: number;
  updated_at_ms: number;
}

export interface ReconstructionReport {
  entity_kind: string;
  entity_id: string;
  verified: boolean;
  reconstructed_hash: string;
  live_hash: string;
  event_count: number;
}

export type NetworkOperation =
  | { op: "CreateSpace"; payload: { name: string; visibility: string; ghost: boolean } }
  | {
      op: "CreateRegion";
      payload: {
        space_id: string;
        name: string;
        prefix?: string | null;
        title?: string | null;
        visibility: string;
        section: number;
        ghost: boolean;
      };
    }
  | {
      op: "CreateWallet";
      payload: {
        region_id: string;
        name: string;
        ghost: boolean;
        approval_threshold?: number | null;
      };
    }
  | {
      op: "AuthorizeWalletKey";
      payload: {
        wallet_id: string;
        authorized_pubkey: string;
        role: string;
        permissions?: string[];
        allowed_token_ids?: string[];
        max_amount_per_op?: number | null;
        expires_at_ms?: number | null;
        pop_nonce?: string | null;
        pop_signature?: string | null;
        participant_identity?: string | null;
      };
    }
  | {
      op: "RevokeWalletKey";
      payload: { wallet_id: string; target_pubkey: string };
    }
  | {
      op: "RotateWalletKey";
      payload: {
        wallet_id: string;
        old_pubkey: string;
        new_pubkey: string;
        role?: string | null;
        pop_nonce?: string | null;
        pop_signature?: string | null;
        participant_identity?: string | null;
      };
    }
  | {
      op: "GrantParticipantScope";
      payload: {
        target_participant_id: string;
        level: string;
        target_id?: string | null;
        expires_at_ms?: number | null;
      };
    }
  | {
      op: "RevokeParticipantScope";
      payload: {
        target_participant_id: string;
        level: string;
        target_id?: string | null;
      };
    }
  | {
      op: "CreateToken";
      payload: {
        wallet_id: string;
        name: string;
        symbol: string;
        initial_supply: number;
        max_supply: number;
        unlimited_supply?: boolean;
        auth_ratio_au: number;
        energy: number;
        drain_bps: number;
        purpose: string;
        external_monetary_value: string;
        ghost: boolean;
      };
    }
  | {
      op: "TransferToken";
      payload: {
        token_id: string;
        from_wallet_id: string;
        to_wallet_id: string;
        amount: number;
        drain_bps?: number | null;
        cosignatures?: Array<[string, string]>;
      };
    }
  | { op: "DrainToken"; payload: { token_id: string; wallet_id: string; amount: number } }
  | {
      op: "AdjustNonTransferableDimensions";
      payload: {
        token_id: string;
        wallet_id: string;
        new_auth_ratio_au?: number | null;
        new_energy?: number | null;
        reason: string;
      };
    }
  | {
      op: "CreateContract";
      payload: { name: string; region_id?: string | null; rules: unknown; actions: unknown[] };
    }
  | { op: "ExecuteContract"; payload: { contract_id: string; action: string; args: unknown } }
  | {
      op: "CreateLoan";
      payload: {
        name: string;
        token_id: string;
        lender_wallet_id: string;
        borrower_wallet_id: string;
        principal: number;
        collateral: number;
        interest_bps: number;
        maturity_at_ms?: number | null;
      };
    }
  | { op: "ExecuteLoan"; payload: { loan_id: string; action: string; amount: number } };
