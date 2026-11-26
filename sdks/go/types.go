package vnetworksdk

type NetworkInfo struct {
	NetworkID            string   `json:"network_id"`
	NetworkName          string   `json:"network_name"`
	Profile              string   `json:"profile"`
	ProtocolVersion      string   `json:"protocol_version"`
	NodeID               string   `json:"node_id"`
	PeerID               string   `json:"peer_id"`
	ListenAddresses      []string `json:"listen_addresses"`
	AdvertisedAddresses  []string `json:"advertised_addresses"`
	BootstrapPeers       []string `json:"bootstrap_peers"`
	Height               uint64   `json:"height"`
	StateRoot            string   `json:"state_root"`
	QuorumThresholdBps   uint16   `json:"quorum_threshold_bps"`
	ValidatorCount       int      `json:"validator_count"`
	AllowBootstrapAtlas  bool     `json:"allow_bootstrap_atlas"`
}

type CreatedEntitySummary struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ConsensusSignature struct {
	ValidatorID        string `json:"validator_id"`
	ValidatorPubkeyHex string `json:"validator_pubkey_hex"`
	Signature          string `json:"signature"`
}

type QuorumCertificate struct {
	CertificateID      string               `json:"certificate_id"`
	NetworkID          string               `json:"network_id"`
	ProposalID         string               `json:"proposal_id"`
	Height             uint64               `json:"height"`
	Epoch              uint64               `json:"epoch"`
	ValidatorSetHash   string               `json:"validator_set_hash,omitempty"`
	StateRoot          string               `json:"state_root"`
	EventRoot          string               `json:"event_root"`
	ApprovedWeight     uint64               `json:"approved_weight"`
	TotalWeight        uint64               `json:"total_weight"`
	QuorumThresholdBps uint16               `json:"quorum_threshold_bps"`
	Signatures         []ConsensusSignature `json:"signatures"`
	FinalizedAtMs      uint64               `json:"finalized_at_ms"`
}

type ProgramSubmission struct {
	ProgramID            string                 `json:"program_id"`
	FileName             string                 `json:"file_name"`
	FileKind             string                 `json:"file_kind"`
	SourceHash           string                 `json:"source_hash"`
	LanguageVersion      string                 `json:"language_version"`
	CompilerVersion      string                 `json:"compiler_version"`
	CompiledProgramHash  string                 `json:"compiled_program_hash"`
	ProtocolVersion      string                 `json:"protocol_version"`
	NetworkID            string                 `json:"network_id"`
	SubmitterParticipant string                 `json:"submitter_participant_id"`
	SubmitterPubkey      string                 `json:"submitter_pubkey"`
	RequestID            string                 `json:"request_id"`
	Nonce                uint64                 `json:"nonce"`
	Status               string                 `json:"status"`
	FailedOperationIndex *int                   `json:"failed_operation_index,omitempty"`
	ErrorMessage         *string                `json:"error_message,omitempty"`
	ResultingEventIDs    []string               `json:"resulting_event_ids"`
	ConsensusCertificate *QuorumCertificate     `json:"consensus_certificate,omitempty"`
	FinalStateRoot       *string                `json:"final_state_root,omitempty"`
	CreatedEntities      []CreatedEntitySummary `json:"created_entities"`
	Outputs              []string               `json:"outputs"`
}

type ReconstructionReport struct {
	EntityKind        string `json:"entity_kind"`
	EntityID          string `json:"entity_id"`
	Verified          bool   `json:"verified"`
	ReconstructedHash string `json:"reconstructed_hash"`
	LiveHash          string `json:"live_hash"`
	EventCount        int    `json:"event_count"`
}
