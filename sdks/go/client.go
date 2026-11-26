package vnetworksdk

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var importRe = regexp.MustCompile(`(?m)^\s*import\s+"([^"]+)"(?:\s+(?:blake3|sha256)\s+"([^"]+)")?(?:\s+as\s+[A-Za-z0-9_]+)?\s*;`)

type Client struct {
	BaseURL            string
	Identity           ClientIdentity
	ExpectedNetworkID  string
	ConnectedNetworkID string
	HTTPClient         *http.Client
	nonce              atomic.Uint64
}

func NewClient(baseURL string, identity ClientIdentity, expectedNetworkID string) *Client {
	c := &Client{
		BaseURL:           strings.TrimRight(baseURL, "/"),
		Identity:          identity,
		ExpectedNetworkID: expectedNetworkID,
		HTTPClient:        &http.Client{Timeout: 30 * time.Second},
	}
	c.nonce.Store(1)
	return c
}

func (c *Client) NextNonce() uint64 {
	return c.nonce.Add(1) - 1
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "req_" + hex.EncodeToString(b[:])
}

func (c *Client) Connect() (NetworkInfo, error) {
	var info NetworkInfo
	if err := c.GetJSON("/v1/network/info", &info); err != nil {
		return info, err
	}
	if info.ProtocolVersion != ProtocolVersion {
		return info, fmt.Errorf("protocol mismatch: %s != %s", info.ProtocolVersion, ProtocolVersion)
	}
	if c.ExpectedNetworkID != "" && info.NetworkID != c.ExpectedNetworkID {
		return info, fmt.Errorf("expected network %s, got %s", c.ExpectedNetworkID, info.NetworkID)
	}
	c.ConnectedNetworkID = info.NetworkID
	return info, nil
}

func (c *Client) resolvedNetworkID() (string, error) {
	if c.ConnectedNetworkID != "" {
		return c.ConnectedNetworkID, nil
	}
	if c.ExpectedNetworkID != "" {
		return c.ExpectedNetworkID, nil
	}
	return "", fmt.Errorf("client must call Connect() before write operations")
}

func (c *Client) Join(scopes []string) (map[string]any, error) {
	return c.JoinWithAuthorizations(scopes, nil)
}

func (c *Client) JoinWithAuthorizations(scopes []string, scopeAuthorizations []map[string]any) (map[string]any, error) {
	if c.ConnectedNetworkID == "" {
		if _, err := c.Connect(); err != nil {
			return nil, err
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"}
	}
	if scopeAuthorizations == nil {
		scopeAuthorizations = []map[string]any{}
	}
	var ch struct {
		ChallengeID string `json:"challenge_id"`
		NetworkID   string `json:"network_id"`
		Nonce       string `json:"nonce"`
	}
	if err := c.PostJSON("/v1/participants/challenge", map[string]any{}, &ch); err != nil {
		return nil, err
	}
	msgBytes, err := CanonicalJSONBytes(map[string]any{
		"challenge_id":       ch.ChallengeID,
		"network_id":         ch.NetworkID,
		"node_pubkey":        c.Identity.NodeKey.PublicKeyHex,
		"nonce":              ch.Nonce,
		"participant_pubkey": c.Identity.ParticipantKey.PublicKeyHex,
		"requested_scopes":   scopes,
	})
	if err != nil {
		return nil, err
	}
	pSig, err := c.Identity.ParticipantKey.Sign(msgBytes)
	if err != nil {
		return nil, err
	}
	nSig, err := c.Identity.NodeKey.Sign(msgBytes)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = c.PostJSON("/v1/participants/join", map[string]any{
		"challenge_id":          ch.ChallengeID,
		"participant_pubkey":    c.Identity.ParticipantKey.PublicKeyHex,
		"node_pubkey":           c.Identity.NodeKey.PublicKeyHex,
		"display_name":          c.Identity.DisplayName,
		"node_kind":             "FULL_NODE",
		"requested_scopes":      scopes,
		"advertised_addresses":  []string{},
		"participant_signature": pSig,
		"node_signature":        nSig,
		"scope_authorizations":  scopeAuthorizations,
	}, &out)
	return out, err
}

func loadModules(source string, baseDir string) (map[string]string, error) {
	modules := make(map[string]string)
	queue := []string{source}
	for len(queue) > 0 {
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		matches := importRe.FindAllStringSubmatch(cur, -1)
		for _, m := range matches {
			imp := m[1]
			if _, ok := modules[imp]; !ok {
				raw, err := os.ReadFile(filepath.Join(baseDir, imp))
				if err != nil {
					return nil, fmt.Errorf("read imported module %s: %w", imp, err)
				}
				txt := string(raw)
				modules[imp] = txt
				queue = append(queue, txt)
			}
		}
	}
	return modules, nil
}

func (c *Client) SubmitVxFile(path string) (ProgramSubmission, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ProgramSubmission{}, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return ProgramSubmission{}, err
	}
	source := string(raw)
	modules, err := loadModules(source, filepath.Dir(abs))
	if err != nil {
		return ProgramSubmission{}, err
	}
	return c.SubmitProgram(filepath.Base(abs), source, modules)
}

func (c *Client) SubmitProgram(fileName, sourceBytes string, modules map[string]string) (ProgramSubmission, error) {
	return c.SubmitProgramWithParams(fileName, sourceBytes, modules, nil)
}

func (c *Client) SubmitProgramWithParams(fileName, sourceBytes string, modules map[string]string, executionParams map[string]any) (ProgramSubmission, error) {
	var sub ProgramSubmission
	if c.ConnectedNetworkID == "" {
		if _, err := c.Connect(); err != nil {
			return sub, err
		}
	}
	networkID, err := c.resolvedNetworkID()
	if err != nil {
		return sub, err
	}
	if modules == nil {
		modules = map[string]string{}
	}
	if executionParams == nil {
		executionParams = map[string]any{}
	}
	requestID := newRequestID()
	nonce := c.NextNonce()
	signingBytes, err := CanonicalJSONBytes(CanonicalProgramSubmitMap(
		c.Identity.ParticipantKey.PublicKeyHex,
		fileName,
		sourceBytes,
		modules,
		networkID,
		requestID,
		nonce,
		executionParams,
	))
	if err != nil {
		return sub, err
	}
	sig, err := c.Identity.ParticipantKey.Sign(signingBytes)
	if err != nil {
		return sub, err
	}
	err = c.PostJSON("/v1/programs/submit", map[string]any{
		"file_name":        fileName,
		"source_bytes":     sourceBytes,
		"modules":          modules,
		"actor_pubkey":     c.Identity.ParticipantKey.PublicKeyHex,
		"network_id":       networkID,
		"request_id":       requestID,
		"nonce":            nonce,
		"signature":        sig,
		"execution_params": executionParams,
	}, &sub)
	return sub, err
}

func (c *Client) SignWalletPoP(
	walletID, participantIdentity, purpose, popNonce string,
	authorizedKey KeypairMaterial,
	expiresAtMs *uint64,
) (string, error) {
	networkID, err := c.resolvedNetworkID()
	if err != nil {
		return "", err
	}
	msgBytes, err := CanonicalJSONBytes(CanonicalWalletPoPMap(
		networkID,
		walletID,
		participantIdentity,
		authorizedKey.PublicKeyHex,
		purpose,
		popNonce,
		expiresAtMs,
	))
	if err != nil {
		return "", err
	}
	return authorizedKey.Sign(msgBytes)
}

func (c *Client) SignTransferApproval(
	tokenID, fromWalletID, toWalletID, amountStr string,
	cosignerKey KeypairMaterial,
	drainBps *uint16,
) (string, error) {
	networkID, err := c.resolvedNetworkID()
	if err != nil {
		return "", err
	}
	msgBytes, err := CanonicalJSONBytes(CanonicalTransferApprovalMap(
		networkID,
		tokenID,
		fromWalletID,
		toWalletID,
		amountStr,
		drainBps,
	))
	if err != nil {
		return "", err
	}
	return cosignerKey.Sign(msgBytes)
}

func (c *Client) SubmitOperation(operation map[string]any) (map[string]any, error) {
	if c.ConnectedNetworkID == "" {
		if _, err := c.Connect(); err != nil {
			return nil, err
		}
	}
	networkID, err := c.resolvedNetworkID()
	if err != nil {
		return nil, err
	}
	requestID := newRequestID()
	nonce := c.NextNonce()
	timestampMs := uint64(time.Now().UnixMilli())
	opBytes, err := CanonicalJSONBytes(operation)
	if err != nil {
		return nil, err
	}
	payloadHash := Blake3Hex(opBytes)
	signingBytes, err := CanonicalJSONBytes(map[string]any{
		"actor_pubkey": c.Identity.ParticipantKey.PublicKeyHex,
		"network_id":   networkID,
		"nonce":        nonce,
		"payload_hash": payloadHash,
		"request_id":   requestID,
		"timestamp_ms": timestampMs,
	})
	if err != nil {
		return nil, err
	}
	sig, err := c.Identity.ParticipantKey.Sign(signingBytes)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = c.PostJSON("/v1/transactions", map[string]any{
		"request_id":   requestID,
		"network_id":   networkID,
		"actor_pubkey": c.Identity.ParticipantKey.PublicKeyHex,
		"nonce":        nonce,
		"timestamp_ms": timestampMs,
		"signature":    sig,
		"operation":    operation,
	}, &out)
	return out, err
}

func (c *Client) VerifyReconstruction(entityKind, entityID string) (ReconstructionReport, error) {
	var rep ReconstructionReport
	err := c.PostJSON("/v1/reconstruction/verify", map[string]string{
		"entity_kind": entityKind,
		"entity_id":   entityID,
	}, &rep)
	return rep, err
}

func (c *Client) GetJSON(path string, out any) error {
	resp, err := c.HTTPClient.Get(c.BaseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

func (c *Client) PostJSON(path string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Post(c.BaseURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

func decodeResponse(resp *http.Response, out any) error {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
