package vnetworksdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

type KeypairMaterial struct {
	KeyRole       string `json:"key_role"`
	DerivedID     string `json:"derived_id"`
	PublicKeyHex  string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
}

func DerivePrefixedID(prefix, domain string, material []byte) string {
	buf := append([]byte(domain+":"), material...)
	digest := Blake3Hex(buf)
	return fmt.Sprintf("%s_%s", prefix, digest[:24])
}

func DeriveParticipantID(pubkeyHex string) string {
	return DerivePrefixedID("prt", "vnetwork/participant-id-v1", []byte(pubkeyHex))
}

func DeriveNodeID(pubkeyHex string) string {
	return DerivePrefixedID("nod", "vnetwork/node-id-v1", []byte(pubkeyHex))
}

func GenerateKeypair(role string) (KeypairMaterial, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeypairMaterial{}, err
	}
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv.Seed())
	did := DeriveParticipantID(pubHex)
	if role == "node" {
		did = DeriveNodeID(pubHex)
	}
	return KeypairMaterial{
		KeyRole:       role,
		DerivedID:     did,
		PublicKeyHex:  pubHex,
		PrivateKeyHex: privHex,
	}, nil
}

func KeypairFromPrivateHex(role, privateHex string) (KeypairMaterial, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(privateHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return KeypairMaterial{}, fmt.Errorf("invalid 32-byte Ed25519 private seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	did := DeriveParticipantID(pubHex)
	if role == "node" {
		did = DeriveNodeID(pubHex)
	}
	return KeypairMaterial{
		KeyRole:       role,
		DerivedID:     did,
		PublicKeyHex:  pubHex,
		PrivateKeyHex: hex.EncodeToString(seed),
	}, nil
}

func (k KeypairMaterial) Sign(message []byte) (string, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(k.PrivateKeyHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("invalid private key seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, message)
	return hex.EncodeToString(sig), nil
}

const (
	ProtocolVersion       = "vector-network/1.0.0"
	LanguageVersion       = "v-langx/1.2.0"
	CompilerVersion       = "vectorspace-compiler/1.2.0"
	DomTransferApprovalV1 = "vnetwork/transfer-approval/v1"

	VerificationVerified    = "VERIFIED"
	VerificationUnverified  = "UNVERIFIED"
	VerificationInvalid     = "INVALID"
	VerificationUnavailable = "UNAVAILABLE"
)

func NormalizeVerificationStatus(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case VerificationVerified:
		return VerificationVerified
	case VerificationUnverified:
		return VerificationUnverified
	case VerificationInvalid:
		return VerificationInvalid
	case VerificationUnavailable:
		return VerificationUnavailable
	default:
		return VerificationUnavailable
	}
}

func isWeakEd25519Pubkey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return true
	}
	allZero := true
	smallOrderOne := pub[0] == 1
	for i, b := range pub {
		if b != 0 {
			allZero = false
			if i > 0 {
				smallOrderOne = false
			}
		}
	}
	return allZero || smallOrderOne
}

func VerifyEd25519(publicKeyHex string, message []byte, signatureHex string) (bool, error) {
	pubClean := strings.TrimSpace(publicKeyHex)
	sigClean := strings.TrimSpace(signatureHex)
	if len(pubClean) != 64 {
		return false, fmt.Errorf("invalid 64-char Ed25519 public key hex")
	}
	if len(sigClean) != 128 {
		return false, fmt.Errorf("invalid 128-char Ed25519 signature hex")
	}
	pub, err := hex.DecodeString(pubClean)
	if err != nil || len(pub) != ed25519.PublicKeySize || isWeakEd25519Pubkey(pub) {
		return false, fmt.Errorf("invalid 32-byte Ed25519 public key")
	}
	sig, err := hex.DecodeString(sigClean)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid 64-byte Ed25519 signature")
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig), nil
}

func CanonicalProgramSubmitMap(
	actorPubkey, fileName, sourceBytes string,
	modules map[string]string,
	networkID, requestID string,
	nonce uint64,
	executionParams map[string]any,
) map[string]any {
	fileKind := "vx"
	if strings.HasSuffix(fileName, ".vdx") {
		fileKind = "vdx"
	}
	moduleHashes := make(map[string]string, len(modules))
	for k, v := range modules {
		moduleHashes[k] = Blake3Hex([]byte(v))
	}
	if executionParams == nil {
		executionParams = map[string]any{}
	}
	return map[string]any{
		"actor_pubkey":     actorPubkey,
		"compiler_version": CompilerVersion,
		"execution_params": executionParams,
		"file_kind":        fileKind,
		"file_name":        fileName,
		"language_version": LanguageVersion,
		"module_hashes":    moduleHashes,
		"network_id":       networkID,
		"nonce":            nonce,
		"protocol_version": ProtocolVersion,
		"request_id":       requestID,
		"source_hash":      Blake3Hex([]byte(sourceBytes)),
	}
}

func CanonicalWalletPoPMap(
	networkID, walletID, participantIdentity, authorizedPubkey, purpose, nonce string,
	expiresAtMs *uint64,
) map[string]any {
	var exp any = nil
	if expiresAtMs != nil {
		exp = *expiresAtMs
	}
	return map[string]any{
		"authorized_pubkey":    authorizedPubkey,
		"expires_at_ms":        exp,
		"network_id":           networkID,
		"nonce":                nonce,
		"participant_identity": participantIdentity,
		"protocol_version":     ProtocolVersion,
		"purpose":              purpose,
		"wallet_id":            walletID,
	}
}

func CanonicalTransferApprovalMap(
	networkID, tokenID, fromWalletID, toWalletID, amountStr string,
) map[string]any {
	return map[string]any{
		"amount":           amountStr,
		"domain":           DomTransferApprovalV1,
		"from_wallet_id":   fromWalletID,
		"network_id":       networkID,
		"protocol_version": ProtocolVersion,
		"to_wallet_id":     toWalletID,
		"token_id":         tokenID,
	}
}

type ClientIdentity struct {
	DisplayName    string          `json:"display_name"`
	ParticipantKey KeypairMaterial `json:"participant_key"`
	NodeKey        KeypairMaterial `json:"node_key"`
	ParticipantID  string          `json:"participant_id"`
	NodeID         string          `json:"node_id"`
}

func GenerateIdentity(displayName string) (ClientIdentity, error) {
	pk, err := GenerateKeypair("participant")
	if err != nil {
		return ClientIdentity{}, err
	}
	nk, err := GenerateKeypair("node")
	if err != nil {
		return ClientIdentity{}, err
	}
	return ClientIdentity{
		DisplayName:    displayName,
		ParticipantKey: pk,
		NodeKey:        nk,
		ParticipantID:  pk.DerivedID,
		NodeID:         nk.DerivedID,
	}, nil
}

func IdentityFromKeys(displayName, participantPrivHex, nodePrivHex string) (ClientIdentity, error) {
	pk, err := KeypairFromPrivateHex("participant", participantPrivHex)
	if err != nil {
		return ClientIdentity{}, err
	}
	nk, err := KeypairFromPrivateHex("node", nodePrivHex)
	if err != nil {
		return ClientIdentity{}, err
	}
	return ClientIdentity{
		DisplayName:    displayName,
		ParticipantKey: pk,
		NodeKey:        nk,
		ParticipantID:  pk.DerivedID,
		NodeID:         nk.DerivedID,
	}, nil
}
