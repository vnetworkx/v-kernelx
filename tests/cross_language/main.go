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
		"b": 2,
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
	})
	fmt.Println(string(out))
}
