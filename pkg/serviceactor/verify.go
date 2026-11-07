// Package serviceactor implements the verification procedures that bind a
// Capability version to a Service Actor (SERVICE_ACTOR_SETTLEMENT_DESIGN
// section 2.4): the common binding steps 1-4, admission-time steps 5-8 before
// a call, and existing-request steps 5-9 from the finalized call transaction
// and its request snapshot. Every input comes from one finalized checkpoint;
// a mismatch is a verification error, never an empty or partial result.
package serviceactor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// StepError names the section 2.4 step a verification failed.
type StepError struct {
	Procedure string // "binding", "admission" or "existing-request"
	Step      int
	Reason    string
}

func (e *StepError) Error() string {
	return fmt.Sprintf("Service Actor %s step %d: %s", e.Procedure, e.Step, e.Reason)
}

func stepError(procedure string, step int, format string, arguments ...any) error {
	return &StepError{Procedure: procedure, Step: step, Reason: fmt.Sprintf(format, arguments...)}
}

// Evidence is everything section 2.4 reads, all from one checkpoint.
type Evidence struct {
	Checkpoint     uint64
	ChainTime      time.Time
	Network        *nativev1.NetworkDomain
	Capability     *nativev1.NativeStateV1
	Agent          *nativev1.NativeStateV1
	Version        string
	ManifestDigest string
	Manifest       nativecore.SoftwareWorkManifestV1
	Actor          *toschain.ActorAccount
}

// ManifestSource returns manifest bytes by digest. The bytes are untrusted
// until checked against the finalized digest.
type ManifestSource interface {
	Manifest(ctx context.Context, digest string) ([]byte, error)
}

// Session is the subset of a reader session the gathering step needs.
type Session interface {
	Checkpoint() uint64
	ChainTime() time.Time
	ResolveRegistry(ctx context.Context, objectID string) (*nativev1.NativeStateV1, bool, error)
	ReadActor(ctx context.Context, actor string) (*toschain.ActorAccount, bool, error)
}

// Gather reads, at the session checkpoint, the Capability, the version's
// manifest (verified against its finalized digest), the owner Agent and the
// actor manifest key 21 names. A missing object is recorded as nil and
// refused by the step that needs it.
func Gather(ctx context.Context, session Session, network *nativev1.NetworkDomain, sources ManifestSource,
	capabilityID, version string) (*Evidence, error) {
	if session == nil || sources == nil || network == nil {
		return nil, errors.New("incomplete Service Actor evidence request")
	}
	evidence := &Evidence{Checkpoint: session.Checkpoint(), ChainTime: session.ChainTime(),
		Network: proto.Clone(network).(*nativev1.NetworkDomain), Version: version}
	capability, found, err := session.ResolveRegistry(ctx, capabilityID)
	if err != nil {
		return nil, err
	}
	if !found || capability.GetCapability() == nil {
		return evidence, stepError("binding", 1, "the Capability is not in finalized state")
	}
	evidence.Capability = capability
	for _, candidate := range capability.GetCapability().Versions {
		if candidate != nil && candidate.Version == version {
			evidence.ManifestDigest = candidate.ManifestDigest
		}
	}
	if evidence.ManifestDigest == "" {
		return evidence, stepError("binding", 1, "the Capability has no version %q", version)
	}
	raw, err := sources.Manifest(ctx, evidence.ManifestDigest)
	if err != nil {
		return evidence, stepError("binding", 1, "the manifest for %s is unavailable: %v", evidence.ManifestDigest, err)
	}
	digest := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(digest[:]) != evidence.ManifestDigest {
		return evidence, stepError("binding", 1, "the manifest bytes do not match the finalized digest")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw)
	if err != nil {
		return evidence, stepError("binding", 1, "the manifest is not a canonical software-work manifest: %v", err)
	}
	evidence.Manifest = manifest
	owner := capability.GetCapability().OwnerAgentId
	agent, found, err := session.ResolveRegistry(ctx, owner)
	if err != nil {
		return nil, err
	}
	if found {
		evidence.Agent = agent
	}
	actor := "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID)
	account, found, err := session.ReadActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	if found {
		evidence.Actor = account
	}
	return evidence, nil
}

// Binding is the result of the common steps 1-4.
type Binding struct {
	Actor         string
	ActorCodeHash [32]byte
	AttestorKeyID [32]byte
	AttestorText  string
	MetadataHash  [32]byte
	Owner         nativecore.MsgAddressV1
}

// VerifyBinding runs steps 1-4. rail is the parsed Quote rail or nil for
// discovery without a Quote. destination is the call destination (before a
// call: the message the buyer builds; after: the call transaction's account).
// allowRevoked admits a version revoked after the call (existing requests).
func VerifyBinding(evidence *Evidence, pinnedCodeHash [32]byte, rail *nativecore.ServiceActorQuoteRailV1,
	proposal *nativev1.QuoteProposalV1, destination string, allowRevoked bool) (*Binding, error) {
	const procedure = "binding"
	if evidence == nil || evidence.Capability == nil || evidence.Capability.GetCapability() == nil {
		return nil, stepError(procedure, 1, "the Capability is not in finalized state")
	}
	capability := evidence.Capability.GetCapability()
	if !proto.Equal(evidence.Capability.Network, evidence.Network) || evidence.Capability.Reference == nil ||
		evidence.Capability.Reference.FinalizedCheckpoint != evidence.Checkpoint {
		return nil, stepError(procedure, 1, "the Capability state is not from the evidence checkpoint and network")
	}
	if capability.Tombstoned {
		return nil, stepError(procedure, 1, "the Capability is tombstoned")
	}
	var version *nativev1.CapabilityVersionV1
	for _, candidate := range capability.Versions {
		if candidate != nil && candidate.Version == evidence.Version {
			version = candidate
		}
	}
	if version == nil || version.ManifestDigest != evidence.ManifestDigest {
		return nil, stepError(procedure, 1, "the version is absent or names another manifest")
	}
	if version.Revoked && !allowRevoked {
		return nil, stepError(procedure, 1, "the version is revoked")
	}
	if evidence.Agent == nil || evidence.Agent.GetAgent() == nil || evidence.Agent.GetAgent().AgentId != capability.OwnerAgentId ||
		evidence.Agent.Reference == nil || evidence.Agent.Reference.FinalizedCheckpoint != evidence.Checkpoint {
		return nil, stepError(procedure, 1, "the owner Agent is not in finalized state at the checkpoint")
	}
	if evidence.Agent.GetAgent().Tombstoned {
		return nil, stepError(procedure, 1, "the owner Agent is tombstoned")
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(evidence.Manifest)
	if err != nil || digest != evidence.ManifestDigest || len(canonical) == 0 || evidence.Manifest.Version != evidence.Version {
		return nil, stepError(procedure, 1, "the manifest does not match the version's digest")
	}
	if proposal != nil && (proposal.CapabilityId != capability.CapabilityId || proposal.CapabilityVersion != evidence.Version ||
		proposal.ProviderAgentId != capability.OwnerAgentId || proposal.ManifestDigest != evidence.ManifestDigest) {
		return nil, stepError(procedure, 1, "the Quote names another Capability, version, provider or manifest")
	}

	settlement := evidence.Manifest.Settlement
	if settlement.Rail != nativecore.ServiceActorRail || settlement.ActorWorkchain != 0 || len(settlement.ActorAccountID) != 32 {
		return nil, stepError(procedure, 2, "manifest key 21 does not name a workchain 0 Service Actor")
	}
	actor := "0:" + hex.EncodeToString(settlement.ActorAccountID)
	if rail != nil && rail.Actor != actor {
		return nil, stepError(procedure, 2, "the Quote actor %s is not manifest key 21 actor %s", rail.Actor, actor)
	}
	if destination != actor {
		return nil, stepError(procedure, 2, "the call destination %s is not manifest key 21 actor %s", destination, actor)
	}
	if evidence.Actor == nil || evidence.Actor.Address != actor {
		return nil, stepError(procedure, 3, "the actor account is not active at the checkpoint")
	}

	codeHash, err := digestBytes(evidence.Actor.CodeHash, "tvm-cell-sha256:")
	if err != nil || codeHash != pinnedCodeHash || !bytes.Equal(settlement.ActorCodeHash, pinnedCodeHash[:]) ||
		(rail != nil && rail.ActorCodeHash != pinnedCodeHash) {
		return nil, stepError(procedure, 3, "the account, manifest key 21, Quote and pinned release code hashes differ")
	}
	if evidence.Actor.Data == nil {
		return nil, stepError(procedure, 3, "the actor data was not decoded")
	}

	keyID, err := mldsa44.ParseKeyIDText(settlement.AttestorKey)
	if err != nil {
		return nil, stepError(procedure, 4, "manifest key 21 attestor is not mldsa44:<key id>")
	}
	if rail != nil && rail.AttestorKeyID != keyID {
		return nil, stepError(procedure, 4, "the Quote attestor differs from manifest key 21")
	}
	if evidence.Manifest.ExecutionSignerAuthorization != nativecore.SettlementAttestorAuthorization(settlement.AttestorKey) {
		return nil, stepError(procedure, 4, "manifest key 18 does not commit to the key 21 attestor text")
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: evidence.Network,
		CapabilityID: capability.CapabilityId, ProviderAgentID: capability.OwnerAgentId, CapabilityVersion: evidence.Version,
		ManifestDigest: evidence.ManifestDigest})
	if err != nil {
		return nil, stepError(procedure, 1, "the NSM1 metadata cannot be built: %v", err)
	}
	return &Binding{Actor: actor, ActorCodeHash: codeHash, AttestorKeyID: keyID, AttestorText: settlement.AttestorKey,
		MetadataHash: metadata, Owner: evidence.Actor.Data.Owner}, nil
}

func digestBytes(value, prefix string) ([32]byte, error) {
	var out [32]byte
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return out, errors.New("invalid digest")
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value[len(prefix):] {
		return out, errors.New("invalid digest")
	}
	copy(out[:], raw)
	return out, nil
}

// Admission is the verified current offer before a call.
type Admission struct {
	Binding   *Binding
	Policy    nativecore.ServiceActorPolicyV1
	TermsHash [32]byte
}

// VerifyAdmission runs admission-time steps 5-8 on top of steps 1-4. buyer
// is the raw address the call will be sent from; rail and proposal may be
// nil only for discovery, in which case step 8 is not run.
func VerifyAdmission(evidence *Evidence, pinnedCodeHash [32]byte, rail *nativecore.ServiceActorQuoteRailV1,
	proposal *nativev1.QuoteProposalV1, buyer string) (*Admission, error) {
	const procedure = "admission"
	destination := ""
	if evidence != nil {
		destination = "0:" + hex.EncodeToString(evidence.Manifest.Settlement.ActorAccountID)
	}
	if rail != nil {
		destination = rail.Actor
	}
	binding, err := VerifyBinding(evidence, pinnedCodeHash, rail, proposal, destination, false)
	if err != nil {
		return nil, err
	}
	policy := evidence.Actor.Data.Policy
	if !evidence.Actor.Data.Active {
		return nil, stepError(procedure, 5, "the actor is inactive")
	}
	if !policy.HasAttestor || policy.AttestorKeyID != binding.AttestorKeyID {
		return nil, stepError(procedure, 5, "the actor's current attestor is not the manifest key 21 attestor")
	}
	derived, err := mldsa44.KeyID(policy.AttestorKey)
	if err != nil || derived != policy.AttestorKeyID {
		return nil, stepError(procedure, 5, "the actor's stored attestor key does not derive its key id")
	}
	if policy.MetadataHash != binding.MetadataHash {
		return nil, stepError(procedure, 6, "the actor's metadata_hash is not NSM1 for this Capability version and network")
	}
	if policy.ProofSchemeHash != nativecore.ServiceActorSoftwareWorkProofScheme {
		return nil, stepError(procedure, 6, "the actor's proof_scheme_hash is not the software-work Receipt scheme")
	}
	if err := checkPolicyBounds(policy); err != nil {
		return nil, stepError(procedure, 7, "%v", err)
	}
	if buyer != "" {
		buyerAddress, err := nativecore.StandardAddress(buyer)
		if err != nil || buyerAddress.Workchain != 0 {
			return nil, stepError(procedure, 7, "the buyer wallet is not a raw workchain 0 address")
		}
		if !policy.OpenAccess && !(policy.HasAuthorizedCaller && policy.AuthorizedCaller.Equal(buyerAddress)) {
			return nil, stepError(procedure, 7, "the actor does not admit this buyer")
		}
	}
	termsHash, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy))
	if err != nil {
		return nil, stepError(procedure, 8, "the current terms cannot be encoded: %v", err)
	}
	if rail != nil {
		if rail.TermsHash != termsHash {
			return nil, stepError(procedure, 8, "the Quote terms_hash is not the actor's current terms_hash")
		}
		if rail.PolicyVersion != policy.PolicyVersion || rail.Price.Cmp(policy.PricePerCall) != 0 ||
			rail.StorageFee.Cmp(policy.StorageFee) != 0 {
			return nil, stepError(procedure, 8, "the Quote policy version, price or storage fee differs from the actor's")
		}
	}
	return &Admission{Binding: binding, Policy: policy, TermsHash: termsHash}, nil
}

func checkPolicyBounds(policy nativecore.ServiceActorPolicyV1) error {
	if policy.ResponseSLA < nativecore.ServiceActorMinimumWindowSeconds || policy.ResponseSLA > nativecore.ServiceActorMaximumWindowSeconds {
		return errors.New("response_sla is outside the contract bounds")
	}
	if policy.RefundClaimWindow < nativecore.ServiceActorMinimumWindowSeconds || policy.RefundClaimWindow > nativecore.ServiceActorMaximumWindowSeconds {
		return errors.New("refund_claim_window is outside the contract bounds")
	}
	if policy.CleanupBounty.Cmp(big.NewInt(nativecore.ServiceActorMinimumCleanupBounty)) < 0 ||
		policy.CleanupBounty.Cmp(big.NewInt(nativecore.ServiceActorMaximumCleanupBounty)) > 0 {
		return errors.New("cleanup_bounty is outside the contract bounds")
	}
	minimum := new(big.Int).Add(big.NewInt(nativecore.ServiceActorMinimumStorageFee), policy.CleanupBounty)
	if policy.StorageFee.Cmp(minimum) < 0 {
		return errors.New("storage_fee is below the minimum plus the cleanup bounty")
	}
	if policy.PricePerCall.Sign() <= 0 {
		return errors.New("price_per_call is zero")
	}
	return nil
}

// ExistingRequest is a request verified from its call transaction alone.
type ExistingRequest struct {
	Binding  *Binding
	Call     toschain.ActorTransaction
	Snapshot nativecore.ServiceActorRequestSnapshotV1
}

// VerifyExistingRequest runs steps 1-4 (a version revoked after the call is
// admitted) and then 5-8 from the finalized call transaction and its request
// snapshot alone; the actor's current policy is never consulted. callAccount
// is the account whose finalized history holds the call transaction.
func VerifyExistingRequest(evidence *Evidence, pinnedCodeHash [32]byte, rail *nativecore.ServiceActorQuoteRailV1,
	proposal *nativev1.QuoteProposalV1, callAccount string, call toschain.ActorTransaction, buyer string,
	requestHash [32]byte) (*ExistingRequest, error) {
	const procedure = "existing-request"
	if rail == nil || proposal == nil {
		return nil, stepError(procedure, 2, "an existing request is verified against its Quote")
	}
	binding, err := VerifyBinding(evidence, pinnedCodeHash, rail, proposal, callAccount, true)
	if err != nil {
		return nil, err
	}
	if call.Kind != toschain.ActorTxCall || call.Call == nil || call.Snapshot == nil {
		return nil, stepError(procedure, 5, "the transaction is not a successful call")
	}
	if call.Sender != buyer {
		return nil, stepError(procedure, 5, "the call was not sent by the buyer")
	}
	if call.Call.RequestHash != hex.EncodeToString(requestHash[:]) {
		return nil, stepError(procedure, 5, "the call carries another request_hash")
	}
	if call.Call.ExpectedTermsHash != hex.EncodeToString(rail.TermsHash[:]) {
		return nil, stepError(procedure, 5, "the call's expected_terms_hash is not the Quote terms_hash")
	}
	snapshot, err := call.Snapshot.Decode()
	if err != nil {
		return nil, stepError(procedure, 6, "the request snapshot does not decode: %v", err)
	}
	caller, ok := snapshot.Caller.RawStandard()
	if !ok || caller != call.Sender || caller != buyer {
		return nil, stepError(procedure, 6, "the snapshot caller is not the call sender and buyer")
	}
	if snapshot.RequestHash != requestHash {
		return nil, stepError(procedure, 6, "the snapshot request_hash differs from the call body")
	}
	terms := snapshot.Terms
	if !terms.HasAttestor || terms.AttestorKeyID != binding.AttestorKeyID {
		return nil, stepError(procedure, 7, "the request snapshotted another attestor or none")
	}
	if snapshot.TermsHash != rail.TermsHash || hex.EncodeToString(snapshot.TermsHash[:]) != call.Call.ExpectedTermsHash {
		return nil, stepError(procedure, 8, "the snapshot terms cell does not hash to the quoted terms_hash")
	}
	if terms.PolicyVersion != rail.PolicyVersion || terms.PricePerCall.Cmp(rail.Price) != 0 || terms.StorageFee.Cmp(rail.StorageFee) != 0 {
		return nil, stepError(procedure, 8, "the snapshot policy version, price or storage fee differs from the Quote")
	}
	if terms.MetadataHash != binding.MetadataHash {
		return nil, stepError(procedure, 8, "the snapshot metadata_hash is not NSM1 for the quoted version and network")
	}
	if terms.ProofSchemeHash != nativecore.ServiceActorSoftwareWorkProofScheme {
		return nil, stepError(procedure, 8, "the snapshot proof_scheme_hash is not the software-work Receipt scheme")
	}
	if snapshot.ResponseDeadline != uint64(call.Now)+uint64(terms.ResponseSLA) {
		return nil, stepError(procedure, 8, "the snapshot response deadline is not the call time plus the SLA")
	}
	if snapshot.RefundClaimDeadline != snapshot.ResponseDeadline+uint64(terms.RefundClaimWindow) {
		return nil, stepError(procedure, 8, "the snapshot refund deadline is not the response deadline plus the window")
	}
	return &ExistingRequest{Binding: binding, Call: call, Snapshot: snapshot}, nil
}
