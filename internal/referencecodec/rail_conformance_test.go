package referencecodec

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// The independent encoder reproduces, from the recorded inputs alone, the
// terms_hash and the SRP2 domain hash of the contract-execution vectors.
func TestReferenceEncoderReproducesContractVectors(t *testing.T) {
	raw, err := os.ReadFile("../../pkg/nativecore/testdata/service-actor-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GlobalID int32  `json:"global_id"`
		Actor    string `json:"actor"`
		Init     struct {
			PricePerCall      string `json:"price_per_call"`
			StorageFee        string `json:"storage_fee"`
			CleanupBounty     string `json:"cleanup_bounty"`
			ResponseSLA       uint32 `json:"response_sla"`
			RefundClaimWindow uint32 `json:"refund_claim_window"`
			MetadataHash      string `json:"metadata_hash"`
			ProofSchemeHash   string `json:"proof_scheme_hash"`
			AttestorKeyID     string `json:"attestor_key_id"`
		} `json:"init"`
		Call struct {
			Caller      string `json:"caller"`
			RequestHash string `json:"request_hash"`
			TermsHash   string `json:"terms_hash"`
			Snapshot    struct {
				RequestID           uint64 `json:"request_id"`
				ResponseDeadline    uint64 `json:"response_deadline"`
				RefundClaimDeadline uint64 `json:"refund_claim_deadline"`
				PolicyVersion       uint32 `json:"policy_version"`
				Price               string `json:"price"`
			} `json:"snapshot"`
		} `json:"call"`
		Respond struct {
			ResponseHash string `json:"response_hash"`
			DomainHash   string `json:"domain_hash"`
		} `json:"respond"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	amount := func(value string) *big.Int {
		parsed, ok := new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatalf("invalid amount %q", value)
		}
		return parsed
	}
	terms, err := ComputeTermsHash(RailTerms{PolicyVersion: v.Call.Snapshot.PolicyVersion, PricePerCall: amount(v.Init.PricePerCall),
		StorageFee: amount(v.Init.StorageFee), CleanupBounty: amount(v.Init.CleanupBounty), ResponseSLA: v.Init.ResponseSLA,
		RefundClaimWindow: v.Init.RefundClaimWindow, MetadataHashHex: v.Init.MetadataHash, ProofSchemeHex: v.Init.ProofSchemeHash,
		HasAttestor: true, AttestorKeyIDHex: v.Init.AttestorKeyID})
	if err != nil || terms != v.Call.TermsHash {
		t.Fatalf("terms_hash %s, recorded %s (%v)", terms, v.Call.TermsHash, err)
	}
	domain, err := ComputeResponseDomainHash(RailResponse{GlobalID: v.GlobalID, Actor: v.Actor, Caller: v.Call.Caller,
		RequestID: v.Call.Snapshot.RequestID, RequestHashHex: v.Call.RequestHash, ResponseHashHex: v.Respond.ResponseHash,
		TermsHashHex: v.Call.TermsHash, Price: amount(v.Call.Snapshot.Price), ResponseDeadline: v.Call.Snapshot.ResponseDeadline,
		RefundClaimDeadline: v.Call.Snapshot.RefundClaimDeadline})
	if err != nil || domain != v.Respond.DomainHash {
		t.Fatalf("SRP2 domain %s, recorded %s (%v)", domain, v.Respond.DomainHash, err)
	}
}
