package vnetworksdk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
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
	NonceStorePath     string
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

// ReserveNonce persists the next nonce before returning it, so a lost HTTP
// response cannot cause the next process to reuse a nonce the node committed.
func (c *Client) ReserveNonce() (uint64, error) {
	networkID, err := c.resolvedNetworkID()
	if err != nil {
		return 0, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("resolve user home for durable nonce store: %w", err)
	}
	storePath := c.NonceStorePath
	if storePath == "" {
		digest := sha256.Sum256([]byte(networkID + "::" + c.Identity.ParticipantKey.PublicKeyHex))
		storePath = filepath.Join(home, ".vnetwork", "nonces", hex.EncodeToString(digest[:])+".json")
	}
	reserved, err := reserveDurableNonce(
		storePath,
		networkID,
		c.Identity.ParticipantKey.PublicKeyHex,
		c.nonce.Load(),
		c.NonceStorePath == "",
	)
	if err != nil {
		return 0, err
	}
	c.nonce.Store(reserved + 1)
	return reserved, nil
}

// NextNonce is retained for source compatibility. New write code should
// prefer ReserveNonce and handle its persistence error explicitly.
func (c *Client) NextNonce() uint64 {
	nonce, err := c.ReserveNonce()
	if err != nil {
		panic(fmt.Sprintf("failed to reserve durable Vector Network request nonce: %v", err))
	}
	return nonce
}

var nonceStoreLocks sync.Map

func reserveDurableNonce(
	filePath, networkID, actorPubkey string,
	minimumNextNonce uint64,
	restrictDirectory bool,
) (uint64, error) {
	filePath, err := filepath.Abs(filePath)
	if err != nil {
		return 0, fmt.Errorf("resolve nonce store path: %w", err)
	}
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("create nonce store directory: %w", err)
	}
	if restrictDirectory {
		if err := os.Chmod(dir, 0o700); err != nil {
			return 0, fmt.Errorf("secure nonce store directory: %w", err)
		}
	}
	lockValue, _ := nonceStoreLocks.LoadOrStore(filePath, &sync.Mutex{})
	mutex := lockValue.(*sync.Mutex)
	mutex.Lock()
	defer mutex.Unlock()

	lockPath := filePath + ".lock"
	var lockFile *os.File
	for attempt := 0; attempt < 400; attempt++ {
		lockFile, err = os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return 0, fmt.Errorf("create durable nonce lock: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if lockFile == nil {
		return 0, fmt.Errorf("timed out acquiring durable nonce lock %s; refusing to risk nonce reuse", lockPath)
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockPath)
	}()
	if _, err := fmt.Fprintf(lockFile, "{\"pid\":%d}", os.Getpid()); err != nil {
		return 0, fmt.Errorf("write durable nonce lock: %w", err)
	}
	if err := lockFile.Sync(); err != nil {
		return 0, fmt.Errorf("sync durable nonce lock: %w", err)
	}

	type nonceRecord struct {
		Version     int    `json:"version"`
		NetworkID   string `json:"network_id"`
		ActorPubkey string `json:"actor_pubkey"`
		NextNonce   uint64 `json:"next_nonce"`
	}
	current := minimumNextNonce
	raw, readErr := os.ReadFile(filePath)
	if readErr == nil {
		var stored nonceRecord
		if err := json.Unmarshal(raw, &stored); err != nil {
			return 0, fmt.Errorf("parse durable nonce state: %w", err)
		}
		if stored.Version != 1 || stored.NetworkID != networkID ||
			stored.ActorPubkey != actorPubkey || stored.NextNonce == 0 {
			return 0, fmt.Errorf("durable nonce state does not match network/participant or is invalid")
		}
		if stored.NextNonce > current {
			current = stored.NextNonce
		}
	} else if !os.IsNotExist(readErr) {
		return 0, fmt.Errorf("read durable nonce state: %w", readErr)
	}
	if current == 0 || current == ^uint64(0) {
		return 0, fmt.Errorf("request nonce exhausted uint64 range")
	}
	next := nonceRecord{Version: 1, NetworkID: networkID, ActorPubkey: actorPubkey, NextNonce: current + 1}
	encoded, err := json.Marshal(next)
	if err != nil {
		return 0, fmt.Errorf("encode durable nonce state: %w", err)
	}
	temp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("create temporary nonce state: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("secure temporary nonce state: %w", err)
	}
	if _, err := temp.Write(append(encoded, '\n')); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("write temporary nonce state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("sync temporary nonce state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, fmt.Errorf("close temporary nonce state: %w", err)
	}
	if err := os.Rename(tempPath, filePath); err != nil {
		return 0, fmt.Errorf("atomically replace durable nonce state: %w", err)
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		return 0, fmt.Errorf("secure durable nonce state: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return current, nil
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
	realBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve module base dir: %w", err)
	}
	realBase, err = filepath.Abs(realBase)
	if err != nil {
		return nil, fmt.Errorf("abs module base dir: %w", err)
	}
	const maxModules = 64
	modules := make(map[string]string)
	queue := []string{source}
	for len(queue) > 0 {
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		matches := importRe.FindAllStringSubmatch(cur, -1)
		for _, m := range matches {
			imp := strings.TrimSpace(m[1])
			if imp == "" || strings.Contains(imp, "\\") || filepath.IsAbs(imp) {
				return nil, fmt.Errorf("unsafe module import path: %s", imp)
			}
			for _, seg := range strings.Split(imp, "/") {
				if seg == ".." {
					return nil, fmt.Errorf("unsafe module import path: %s", imp)
				}
			}
			if _, ok := modules[imp]; !ok {
				if len(modules) >= maxModules {
					return nil, fmt.Errorf("imported module count exceeded limit (%d)", maxModules)
				}
				candidate := filepath.Join(realBase, filepath.FromSlash(imp))
				realTarget, err := filepath.EvalSymlinks(candidate)
				if err != nil {
					return nil, fmt.Errorf("resolve imported module %s: %w", imp, err)
				}
				rel, err := filepath.Rel(realBase, realTarget)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
					return nil, fmt.Errorf("module import path escapes base directory: %s", imp)
				}
				raw, err := os.ReadFile(realTarget)
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
	nonce, err := c.ReserveNonce()
	if err != nil {
		return sub, err
	}
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
	))
	if err != nil {
		return "", err
	}
	return cosignerKey.Sign(msgBytes)
}

func (c *Client) UpdateWalletReceivePolicy(walletID, mode string, allowedSenders []string) (map[string]any, error) {
	if allowedSenders == nil {
		allowedSenders = []string{}
	}
	return c.SubmitOperation(map[string]any{
		"op": "UpdateWalletReceivePolicy",
		"payload": map[string]any{
			"wallet_id":       walletID,
			"mode":            mode,
			"allowed_senders": allowedSenders,
		},
	})
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

func (c *Client) GetNetworkInfo() (NetworkInfo, error) {
	var info NetworkInfo
	err := c.GetJSON("/v1/network/info", &info)
	return info, err
}

func (c *Client) GetNetworkStatus() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/network/status", &out)
	return out, err
}

func (c *Client) ListNodes() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/nodes", &out)
	return out, err
}

func (c *Client) GetNodeDetails(nodeID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/nodes/"+nodeID, &out)
	return out, err
}

func (c *Client) GetExplorerNetwork() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/explorer/network", &out)
	return out, err
}

func (c *Client) ParticipantStatus(participantID string) (map[string]any, error) {
	if strings.TrimSpace(participantID) == "" {
		participantID = c.Identity.ParticipantID
	}
	var out map[string]any
	err := c.GetJSON("/v1/participants/"+participantID+"/scope", &out)
	return out, err
}

func (c *Client) CompileSource(fileName, sourceBytes string, modules map[string]string) (map[string]any, error) {
	if modules == nil {
		modules = map[string]string{}
	}
	var out map[string]any
	err := c.PostJSON("/v1/language/compile", map[string]any{
		"file_name":    fileName,
		"source_bytes": sourceBytes,
		"modules":      modules,
	}, &out)
	return out, err
}

func (c *Client) GetProgram(programID string) (ProgramSubmission, error) {
	var out ProgramSubmission
	err := c.GetJSON("/v1/programs/"+programID, &out)
	return out, err
}

func (c *Client) GetProgramStatus(programID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/programs/"+programID+"/status", &out)
	return out, err
}

func (c *Client) GetTransaction(txID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/transactions/"+txID, &out)
	return out, err
}

func (c *Client) ListSpaces() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/spaces", &out)
	return out, err
}

func (c *Client) ListRegions() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/regions", &out)
	return out, err
}

func (c *Client) ListWallets() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/wallets", &out)
	return out, err
}

func (c *Client) GetWallet(walletID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/wallets/"+walletID, &out)
	return out, err
}

func (c *Client) ListTokens() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/tokens", &out)
	return out, err
}

func (c *Client) GetToken(tokenID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/tokens/"+tokenID, &out)
	return out, err
}

func (c *Client) ListContracts() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/contracts", &out)
	return out, err
}

func (c *Client) GetContract(contractID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/contracts/"+contractID, &out)
	return out, err
}

func (c *Client) ListLoans() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/loans", &out)
	return out, err
}

func (c *Client) GetLoan(loanID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/loans/"+loanID, &out)
	return out, err
}

func (c *Client) CreateContract(name string, regionID *string, rules any, actions []any) (map[string]any, error) {
	if actions == nil {
		actions = []any{}
	}
	return c.SubmitOperation(map[string]any{
		"op": "CreateContract",
		"payload": map[string]any{
			"name":      name,
			"region_id": regionID,
			"rules":     rules,
			"actions":   actions,
		},
	})
}

func (c *Client) ExecuteContract(contractID, action string, args any) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	return c.SubmitOperation(map[string]any{
		"op": "ExecuteContract",
		"payload": map[string]any{
			"contract_id": contractID,
			"action":      action,
			"args":        args,
		},
	})
}

func (c *Client) CreateLoan(
	name, tokenID, lenderWalletID, borrowerWalletID string,
	principal, collateral, interestBps uint64,
	maturityAtMs *uint64,
) (map[string]any, error) {
	return c.SubmitOperation(map[string]any{
		"op": "CreateLoan",
		"payload": map[string]any{
			"name":               name,
			"token_id":           tokenID,
			"lender_wallet_id":   lenderWalletIdOr(lenderWalletID),
			"borrower_wallet_id": borrowerWalletID,
			"principal":          principal,
			"collateral":         collateral,
			"interest_bps":       interestBps,
			"maturity_at_ms":     maturityAtMs,
		},
	})
}

func lenderWalletIdOr(v string) string {
	return v
}

func (c *Client) ExecuteLoan(loanID, action string, amount uint64) (map[string]any, error) {
	return c.SubmitOperation(map[string]any{
		"op": "ExecuteLoan",
		"payload": map[string]any{
			"loan_id": loanID,
			"action":  action,
			"amount":  amount,
		},
	})
}

func (c *Client) GetLedgerEvents() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/ledger/events", &out)
	return out, err
}

func (c *Client) GetLedgerProofs() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/ledger/proofs", &out)
	return out, err
}

func (c *Client) GetConsensusStatus() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/consensus/status", &out)
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

func (c *Client) VerifyLedgerReplay() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/ledger/replay", &out)
	return out, err
}

func (c *Client) VerifyTokenSupply(tokenID string) (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/tokens/"+tokenID+"/supply", &out)
	return out, err
}

func (c *Client) GetEquivocations() (map[string]any, error) {
	var out map[string]any
	err := c.GetJSON("/v1/consensus/equivocations", &out)
	return out, err
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
