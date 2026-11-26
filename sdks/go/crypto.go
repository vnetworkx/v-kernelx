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
