package vnetworksdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

func TestIdentityAndVerificationHelpers(t *testing.T) {
	seedP := "1111111111111111111111111111111111111111111111111111111111111111"
	seedN := "2222222222222222222222222222222222222222222222222222222222222222"
	id, err := IdentityFromKeys("go-unit-test", seedP, seedN)
	if err != nil {
		t.Fatalf("IdentityFromKeys failed: %v", err)
	}
	if id.ParticipantID == id.NodeID {
		t.Fatalf("participant and node IDs must be domain separated")
	}

	msg := []byte(`{"a":1,"b":2}`)
	sig, err := id.ParticipantKey.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	ok, err := VerifyEd25519(id.ParticipantKey.PublicKeyHex, msg, sig)
	if err != nil || !ok {
		t.Fatalf("VerifyEd25519 expected true, got ok=%v err=%v", ok, err)
	}

	// Weak keys must be rejected
	if ok, err := VerifyEd25519("0000000000000000000000000000000000000000000000000000000000000000", msg, sig); ok || err == nil {
		t.Fatalf("all-zero public key must be rejected")
	}

	if NormalizeVerificationStatus("verified") != VerificationVerified {
		t.Fatalf("expected VERIFIED")
	}
	if NormalizeVerificationStatus("UNAVAILABLE") != VerificationUnavailable {
		t.Fatalf("expected UNAVAILABLE")
	}
	if NormalizeVerificationStatus("UNKNOWN") != VerificationUnavailable {
		t.Fatalf("unknown must normalize to UNAVAILABLE")
	}
}

func TestClientEndpointsParityAndSignedOperations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/network/info":
			_ = json.NewEncoder(w).Encode(NetworkInfo{
				NetworkID:          "vector-devnet-1",
				NetworkName:        "Devnet",
				Profile:            "DEVELOPMENT",
				ProtocolVersion:    ProtocolVersion,
				NodeID:             "nod_1",
				PeerID:             "peer_1",
				Height:             3,
				StateRoot:          "root_3",
				QuorumThresholdBps: 6667,
				ValidatorCount:     4,
			})
		case "/v1/explorer/network":
			_ = json.NewEncoder(w).Encode(map[string]any{"spaces": []any{}, "ghost_entities": []any{}})
		case "/v1/transactions":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"transaction_id": "tx_1",
				"status":         "COMMITTED",
				"request_id":     req["request_id"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	id, err := GenerateIdentity("go-client-test")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	client := NewClient(srv.URL, id, "vector-devnet-1")
	info, err := client.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if info.NetworkID != "vector-devnet-1" {
		t.Fatalf("unexpected network_id %s", info.NetworkID)
	}
	if _, err := client.GetExplorerNetwork(); err != nil {
		t.Fatalf("GetExplorerNetwork failed: %v", err)
	}
	res, err := client.CreateContract("EscrowVault", nil, map[string]any{"max_amount_per_op": 100}, []any{})
	if err != nil {
		t.Fatalf("CreateContract failed: %v", err)
	}
	if res["status"] != "COMMITTED" {
		t.Fatalf("unexpected contract receipt: %v", res)
	}
	if _, err := client.ExecuteLoan("lon_1", "draw", 50); err != nil {
		t.Fatalf("ExecuteLoan failed: %v", err)
	}
}


func TestDurableNonceReservationsSurviveRestartAndSerializeClients(t *testing.T) {
	identity, err := GenerateIdentity("go-durable-nonce")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	storePath := filepath.Join(t.TempDir(), "request-nonce.json")
	clients := []*Client{
		NewClient("http://127.0.0.1:8080", identity, "nonce-network"),
		NewClient("http://127.0.0.1:8080", identity, "nonce-network"),
	}
	for _, client := range clients {
		client.ConnectedNetworkID = "nonce-network"
		client.NonceStorePath = storePath
	}

	reserved := make(chan uint64, len(clients))
	errors := make(chan error, len(clients))
	var wg sync.WaitGroup
	for _, client := range clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			nonce, reserveErr := c.ReserveNonce()
			if reserveErr != nil {
				errors <- reserveErr
				return
			}
			reserved <- nonce
		}(client)
	}
	wg.Wait()
	close(reserved)
	close(errors)
	for reserveErr := range errors {
		t.Fatalf("ReserveNonce failed: %v", reserveErr)
	}
	got := map[uint64]bool{}
	for nonce := range reserved {
		got[nonce] = true
	}
	if len(got) != 2 || !got[1] || !got[2] {
		t.Fatalf("concurrent clients should reserve unique nonces 1 and 2, got %v", got)
	}

	restarted := NewClient("http://127.0.0.1:8080", identity, "nonce-network")
	restarted.ConnectedNetworkID = "nonce-network"
	restarted.NonceStorePath = storePath
	nonce, err := restarted.ReserveNonce()
	if err != nil {
		t.Fatalf("ReserveNonce after restart failed: %v", err)
	}
	if nonce != 3 {
		t.Fatalf("expected persisted next nonce 3 after restart, got %d", nonce)
	}
}
