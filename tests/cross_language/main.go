package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	vnetwork "github.com/vnetworkx/vnetwork-sdk-go"
)

func main() {
	const seedHex = "1111111111111111111111111111111111111111111111111111111111111111"
	const nodeSeedHex = "2222222222222222222222222222222222222222222222222222222222222222"
	id, err := vnetwork.IdentityFromKeys("parity", seedHex, nodeSeedHex)
	if err != nil {
		log.Fatal(err)
	}
	multiChunk := strings.Repeat("vector-network-", 200)
	canon, err := vnetwork.CanonicalJSONBytes(map[string]any{
		"b":    2,
		"nil":  nil,
		"html": "<a>&",
		"a": map[string]any{
			"z": true,
			"m": []int{3, 1, 2},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	sig, err := id.ParticipantKey.Sign(canon)
	if err != nil {
		log.Fatal(err)
	}
	ok, err := vnetwork.VerifyEd25519(id.ParticipantKey.PublicKeyHex, canon, sig)
	if err != nil || !ok {
		log.Fatalf("Go Ed25519 self-verify failed: %v", err)
	}

	submitCanon, err := vnetwork.CanonicalJSONBytes(vnetwork.CanonicalProgramSubmitMap(
		id.ParticipantKey.PublicKeyHex,
		"bootstrap-atlas.vx",
		"Wallet Main;",
		map[string]string{"policies.vdx": "Space ATLAS;"},
		"vector-devnet-1",
		"req_0001",
		7,
		map[string]any{"dry": false},
	))
	if err != nil {
		log.Fatal(err)
	}
	submitSig, err := id.ParticipantKey.Sign(submitCanon)
	if err != nil {
		log.Fatal(err)
	}

	popCanon, err := vnetwork.CanonicalJSONBytes(vnetwork.CanonicalWalletPoPMap(
		"vector-devnet-1",
		"wal_demo",
		id.ParticipantID,
		id.NodeKey.PublicKeyHex,
		"wallet_key_authorization",
		"pop_1",
		nil,
	))
	if err != nil {
		log.Fatal(err)
	}
	popSig, err := id.NodeKey.Sign(popCanon)
	if err != nil {
		log.Fatal(err)
	}

	xferCanon, err := vnetwork.CanonicalJSONBytes(vnetwork.CanonicalTransferApprovalMap(
		"vector-devnet-1",
		"tok_atlas",
		"wal_a",
		"wal_b",
		"250",
		nil,
	))
	if err != nil {
		log.Fatal(err)
	}
	xferSig, err := id.ParticipantKey.Sign(xferCanon)
	if err != nil {
		log.Fatal(err)
	}

	out, _ := json.Marshal(map[string]any{
		"lang":               "go",
		"empty_b3":           vnetwork.Blake3Hex([]byte("")),
		"hello_b3":           vnetwork.Blake3Hex([]byte("hello world")),
		"multi_b3":           vnetwork.Blake3Hex([]byte(multiChunk)),
		"canon_str":          string(canon),
		"participant_pubkey": id.ParticipantKey.PublicKeyHex,
		"participant_id":     id.ParticipantID,
		"node_id":            id.NodeID,
		"sig":                sig,
		"submit_str":         string(submitCanon),
		"submit_sig":         submitSig,
		"pop_str":            string(popCanon),
		"pop_sig":            popSig,
		"xfer_str":           string(xferCanon),
		"xfer_sig":           xferSig,
	})
	fmt.Println(string(out))
}
