package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// serviceActorVectors is the contract-execution vector file exported by the
// tos sandbox test conformance_vectors_come_from_contract_execution, copied
// byte for byte. Nothing here is computed by Go and written back.
type serviceActorVectors struct {
	Schema           string `json:"schema"`
	ContractCodeHash string `json:"contract_code_hash"`
	ContractCodeBOC  string `json:"contract_code_boc_base64"`
	GlobalID         int32  `json:"global_id"`
	Actor            string `json:"actor"`
	Init             struct {
		Owner                   string `json:"owner"`
		OpenAccess              bool   `json:"open_access"`
		PricePerCall            string `json:"price_per_call"`
		StorageFee              string `json:"storage_fee"`
		CleanupBounty           string `json:"cleanup_bounty"`
		RateLimitPerDay         uint32 `json:"rate_limit_per_day"`
		ResponseSLA             uint32 `json:"response_sla"`
		RefundClaimWindow       uint32 `json:"refund_claim_window"`
		MetadataHash            string `json:"metadata_hash"`
		ProofSchemeHash         string `json:"proof_scheme_hash"`
		AttestorSeedHex         string `json:"attestor_seed_hex"`
		AttestorPublicKeySHA256 string `json:"attestor_public_key_sha256"`
		AttestorKeyID           string `json:"attestor_key_id"`
	} `json:"init"`
	DeployDataBOC string `json:"deploy_data_boc_base64"`
	Call          struct {
		Now          uint64 `json:"now"`
		Caller       string `json:"caller"`
		QueryID      uint64 `json:"query_id"`
		RequestHash  string `json:"request_hash"`
		BodyBOC      string `json:"body_boc_base64"`
		TermsHash    string `json:"terms_hash"`
		TermsCellBOC string `json:"terms_cell_boc_base64"`
		SnapshotBOC  string `json:"snapshot_body_boc_base64"`
		Snapshot     struct {
			RequestID           uint64 `json:"request_id"`
			ResponseDeadline    uint64 `json:"response_deadline"`
			RefundClaimDeadline uint64 `json:"refund_claim_deadline"`
			PolicyVersion       uint32 `json:"policy_version"`
			Price               string `json:"price"`
			AttestorKeyID       string `json:"attestor_key_id"`
		} `json:"snapshot"`
		DataAfterBOC string `json:"data_after_boc_base64"`
	} `json:"call"`
	Respond struct {
		ResponseHash     string `json:"response_hash"`
		DomainHash       string `json:"domain_hash"`
		SignatureContext string `json:"signature_context"`
	} `json:"respond"`
}

func loadServiceActorVectors(t *testing.T) serviceActorVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/service-actor-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors serviceActorVectors
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vectors); err != nil || vectors.Schema != "tos.service.actor.v1.vectors" {
		t.Fatalf("vector file: %v", err)
	}
	return vectors
}

func vectorCellBOC(t *testing.T, encoded string) *cell.Cell {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func vectorHash(t *testing.T, value string) [32]byte {
	t.Helper()
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("invalid vector hash %q", value)
	}
	copy(out[:], raw)
	return out
}

func vectorAmount(t *testing.T, value string) *big.Int {
	t.Helper()
	amount, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid vector amount %q", value)
	}
	return amount
}

func vectorAddress(t *testing.T, raw string) MsgAddressV1 {
	t.Helper()
	address, err := StandardAddress(raw)
	if err != nil {
		t.Fatalf("vector address %q: %v", raw, err)
	}
	return address
}

func TestConformanceCodeHash(t *testing.T) {
	v := loadServiceActorVectors(t)
	code := vectorCellBOC(t, v.ContractCodeBOC)
	if got := "tvm-cell-sha256:" + hex.EncodeToString(code.Hash()); got != v.ContractCodeHash {
		t.Fatalf("code hash %s, recorded %s", got, v.ContractCodeHash)
	}
}

// expectInitPolicy checks a decoded policy against the recorded init.
func expectInitPolicy(t *testing.T, v serviceActorVectors, policy ServiceActorPolicyV1) {
	t.Helper()
	owner := vectorAddress(t, v.Init.Owner)
	if policy.PolicyVersion != 0 || policy.PricePerCall.Cmp(vectorAmount(t, v.Init.PricePerCall)) != 0 ||
		policy.StorageFee.Cmp(vectorAmount(t, v.Init.StorageFee)) != 0 || policy.CleanupBounty.Cmp(vectorAmount(t, v.Init.CleanupBounty)) != 0 ||
		policy.ResponseSLA != v.Init.ResponseSLA || policy.RefundClaimWindow != v.Init.RefundClaimWindow ||
		policy.OpenAccess != v.Init.OpenAccess || policy.HasAuthorizedCaller || !policy.AuthorizedCaller.Equal(owner) ||
		policy.RateLimitPerDay != v.Init.RateLimitPerDay || policy.MetadataHash != vectorHash(t, v.Init.MetadataHash) ||
		policy.ProofSchemeHash != vectorHash(t, v.Init.ProofSchemeHash) || !policy.HasAttestor ||
		policy.AttestorKeyID != vectorHash(t, v.Init.AttestorKeyID) {
		t.Fatalf("policy differs from the recorded init: %+v", policy)
	}
	keyDigest := sha256.Sum256(policy.AttestorKey)
	derived, err := mldsa44.KeyID(policy.AttestorKey)
	if err != nil || hex.EncodeToString(keyDigest[:]) != v.Init.AttestorPublicKeySHA256 || derived != policy.AttestorKeyID {
		t.Fatal("the stored attestor key is not the recorded key")
	}
}

func TestConformanceDeployData(t *testing.T) {
	v := loadServiceActorVectors(t)
	data, err := DecodeServiceActorData(vectorCellBOC(t, v.DeployDataBOC))
	if err != nil {
		t.Fatal(err)
	}
	if !data.Owner.Equal(vectorAddress(t, v.Init.Owner)) || !data.Active || data.NextRequestID != 0 || data.PendingCount != 0 ||
		data.LiveCount != 0 || len(data.Pending) != 0 || len(data.Refunds) != 0 || len(data.CallerLiveCounts) != 0 {
		t.Fatalf("deployed data root: %+v", data)
	}
	a := data.Accounting
	if a.WithdrawableRevenue.Sign() != 0 || a.LockedStorageFees.Sign() != 0 || a.PendingLiability.Sign() != 0 ||
		a.RefundableLiability.Sign() != 0 || a.CallDay != 0 || a.CallsToday != 0 {
		t.Fatalf("deployed accounting: %+v", a)
	}
	expectInitPolicy(t, v, data.Policy)
	if err := ValidateServiceActorLiveState(data); err != nil {
		t.Fatal(err)
	}
}

func TestConformanceDataAfterAdmission(t *testing.T) {
	v := loadServiceActorVectors(t)
	data, err := DecodeServiceActorData(vectorCellBOC(t, v.Call.DataAfterBOC))
	if err != nil {
		t.Fatal(err)
	}
	if !data.Owner.Equal(vectorAddress(t, v.Init.Owner)) || !data.Active || data.NextRequestID != 1 || data.PendingCount != 1 ||
		data.LiveCount != 1 || len(data.Refunds) != 0 {
		t.Fatalf("data after admission: %+v", data)
	}
	expectInitPolicy(t, v, data.Policy)
	entry, ok := data.Pending[v.Call.Snapshot.RequestID]
	caller := vectorAddress(t, v.Call.Caller)
	if !ok || !entry.Caller.Equal(caller) || entry.Price.Cmp(vectorAmount(t, v.Call.Snapshot.Price)) != 0 ||
		entry.StorageFee.Cmp(vectorAmount(t, v.Init.StorageFee)) != 0 || entry.CleanupBounty.Cmp(vectorAmount(t, v.Init.CleanupBounty)) != 0 ||
		entry.ResponseDeadline != v.Call.Snapshot.ResponseDeadline || entry.RefundClaimDeadline != v.Call.Snapshot.RefundClaimDeadline ||
		entry.PolicyVersion != v.Call.Snapshot.PolicyVersion || entry.RequestHash != vectorHash(t, v.Call.RequestHash) ||
		entry.TermsHash != vectorHash(t, v.Call.TermsHash) || !entry.HasAttestor ||
		entry.AttestorKeyID != vectorHash(t, v.Call.Snapshot.AttestorKeyID) || !bytes.Equal(entry.AttestorKey, data.Policy.AttestorKey) {
		t.Fatalf("pending entry differs from the snapshot: %+v", entry)
	}
	a := data.Accounting
	if a.WithdrawableRevenue.Sign() != 0 || a.PendingLiability.Cmp(entry.Price) != 0 || a.LockedStorageFees.Cmp(entry.StorageFee) != 0 ||
		a.RefundableLiability.Sign() != 0 || uint64(a.CallDay) != v.Call.Now/86400 || a.CallsToday != 1 {
		t.Fatalf("accounting after admission: %+v", a)
	}
	key, err := caller.SliceHash()
	if err != nil || data.CallerLiveCounts[key] != 1 || len(data.CallerLiveCounts) != 1 {
		t.Fatal("the caller live count is not one entry for the caller")
	}
	if err := ValidateServiceActorLiveState(data); err != nil {
		t.Fatal(err)
	}
}

func TestConformanceCallBody(t *testing.T) {
	v := loadServiceActorVectors(t)
	recorded := vectorCellBOC(t, v.Call.BodyBOC)
	built := BuildServiceActorCallBody(v.Call.QueryID, vectorHash(t, v.Call.RequestHash), vectorHash(t, v.Call.TermsHash))
	if !bytes.Equal(built.Hash(), recorded.Hash()) {
		t.Fatal("the call body builder differs from the recorded call body")
	}
	decoded, err := DecodeServiceActorInbound(recorded)
	if err != nil || decoded.Opcode != ServiceActorCallOpcode || decoded.QueryID != v.Call.QueryID ||
		decoded.RequestHash != vectorHash(t, v.Call.RequestHash) || decoded.ExpectedTermsHash != vectorHash(t, v.Call.TermsHash) {
		t.Fatalf("recorded call body decodes to %+v, %v", decoded, err)
	}
}

func TestConformanceTerms(t *testing.T) {
	v := loadServiceActorVectors(t)
	data, err := DecodeServiceActorData(vectorCellBOC(t, v.DeployDataBOC))
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildServiceActorTermsCell(TermsOfPolicy(data.Policy))
	if err != nil {
		t.Fatal(err)
	}
	recorded := vectorCellBOC(t, v.Call.TermsCellBOC)
	want := vectorHash(t, v.Call.TermsHash)
	if !bytes.Equal(built.Hash(), want[:]) || !bytes.Equal(recorded.Hash(), want[:]) {
		t.Fatalf("terms: built %x, recorded cell %x, recorded terms_hash %x", built.Hash(), recorded.Hash(), want)
	}
	decoded, err := DecodeServiceActorTermsCell(recorded)
	if err != nil || decoded.PricePerCall.Cmp(data.Policy.PricePerCall) != 0 || decoded.AttestorKeyID != data.Policy.AttestorKeyID {
		t.Fatalf("recorded terms cell decodes to %+v, %v", decoded, err)
	}
}

func TestConformanceSnapshot(t *testing.T) {
	v := loadServiceActorVectors(t)
	snapshot, err := DecodeServiceActorRequestSnapshot(vectorCellBOC(t, v.Call.SnapshotBOC))
	if err != nil {
		t.Fatal(err)
	}
	s := v.Call.Snapshot
	if snapshot.RequestID != s.RequestID || !snapshot.Caller.Equal(vectorAddress(t, v.Call.Caller)) ||
		snapshot.RequestHash != vectorHash(t, v.Call.RequestHash) || snapshot.ResponseDeadline != s.ResponseDeadline ||
		snapshot.RefundClaimDeadline != s.RefundClaimDeadline || snapshot.Terms.PolicyVersion != s.PolicyVersion ||
		snapshot.Terms.PricePerCall.Cmp(vectorAmount(t, s.Price)) != 0 || snapshot.Terms.AttestorKeyID != vectorHash(t, s.AttestorKeyID) ||
		!snapshot.Terms.HasAttestor || snapshot.TermsHash != vectorHash(t, v.Call.TermsHash) ||
		snapshot.ResponseDeadline != v.Call.Now+uint64(v.Init.ResponseSLA) {
		t.Fatalf("snapshot differs from the recorded fields: %+v", snapshot)
	}
}

func TestConformanceRespondDomain(t *testing.T) {
	v := loadServiceActorVectors(t)
	snapshot, err := DecodeServiceActorRequestSnapshot(vectorCellBOC(t, v.Call.SnapshotBOC))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := ServiceActorResponseDomainHash(v.GlobalID, v.Actor, snapshot, vectorHash(t, v.Respond.ResponseHash))
	if err != nil || domain != vectorHash(t, v.Respond.DomainHash) {
		t.Fatalf("SRP2 domain %x, recorded %s (%v)", domain, v.Respond.DomainHash, err)
	}
	if v.Respond.SignatureContext != ServiceActorRespondContext {
		t.Fatal("the respond signature context differs")
	}
}
