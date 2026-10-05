// Package executiongate verifies finalized Native commercial authority and
// atomically binds one paid escrow to one exact provider execution intent.
package executiongate

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

type PaidDemandEscrowResolver interface {
	ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error)
}

type NativeResolver interface {
	ResolveFinalizedState(context.Context, string, string) (*nativev1.NativeStateV1, bool, time.Time, error)
}

type Gate struct {
	store         *store
	native        NativeResolver
	network       *nativev1.NetworkDomain
	registryHash  string
	providerAgent string
	provider      string
	manifest      string
	transport     string
	signerAuth    string
	timeout       time.Duration
	now           func() time.Time
	paidEscrow    PaidDemandEscrowResolver
	agreement     commerce.AgentAgreementBody
	offerResolver commerce.ProviderOfferKeyResolver
}

type PaidDemandConfig struct {
	Directory                    string
	EscrowResolver               PaidDemandEscrowResolver
	NativeResolver               NativeResolver
	Network                      *nativev1.NetworkDomain
	RegistryCodeHash             string
	ProviderAgentID              string
	ProviderAddress              string
	ManifestDigest               string
	TransportDigest              string
	ExecutionSignerAuthorization string
	Agreement                    commerce.AgentAgreementBody
	ProviderOfferResolver        commerce.ProviderOfferKeyResolver
	Timeout                      time.Duration
	Now                          func() time.Time
}

// Request is the transport-independent execution identity. The same funded
// Quote and escrow may be claimed by exactly one complete request.
type Request struct {
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
}

// Evidence records the finalized chain authority used when admitting work.
type Evidence struct {
	NetworkID                     string `json:"network_id"`
	ProviderAgentID               string `json:"provider_agent_id"`
	ProviderAddress               string `json:"provider_address"`
	CapabilityID                  string `json:"capability_id"`
	CapabilityVersion             string `json:"capability_version"`
	ManifestDigest                string `json:"manifest_digest"`
	QuoteCommitment               string `json:"quote_commitment"`
	EscrowAddress                 string `json:"escrow_address"`
	EscrowCodeHash                string `json:"escrow_code_hash"`
	RegistryCodeHash              string `json:"registry_code_hash"`
	EscrowTransactionHash         string `json:"escrow_transaction_hash"`
	AgentTransactionHash          string `json:"agent_transaction_hash"`
	CapabilityTransactionHash     string `json:"capability_transaction_hash"`
	EscrowFinalizedCheckpoint     uint64 `json:"escrow_finalized_checkpoint"`
	AgentFinalizedCheckpoint      uint64 `json:"agent_finalized_checkpoint"`
	CapabilityFinalizedCheckpoint uint64 `json:"capability_finalized_checkpoint"`
	AgreementBodyDigest           string `json:"agreement_body_digest,omitempty"`
	ProviderOfferDigest           string `json:"provider_offer_digest,omitempty"`
	AcceptedAtUnix                uint64 `json:"accepted_at_unix,omitempty"`
}

func NewPaidDemand(c PaidDemandConfig) (*Gate, error) {
	if c.EscrowResolver == nil || c.NativeResolver == nil || c.Network == nil || c.ProviderOfferResolver == nil ||
		c.Network.NetworkId == "" || !cellDigest(c.RegistryCodeHash) || !agentID(c.ProviderAgentID) ||
		!rawAddress(c.ProviderAddress) || !shaDigest(c.ManifestDigest) || !shaDigest(c.TransportDigest) ||
		!shaDigest(c.ExecutionSignerAuthorization) || commerce.ValidateAgreementBody(c.Agreement) != nil {
		return nil, errors.New("invalid Paid Demand execution gate configuration")
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return nil, errors.New("invalid Paid Demand execution gate timeout")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	store, err := newStore(c.Directory)
	if err != nil {
		return nil, err
	}
	return &Gate{store: store, paidEscrow: c.EscrowResolver, native: c.NativeResolver,
		network: proto.Clone(c.Network).(*nativev1.NetworkDomain), registryHash: c.RegistryCodeHash,
		providerAgent: c.ProviderAgentID, provider: c.ProviderAddress, manifest: c.ManifestDigest,
		transport: c.TransportDigest, signerAuth: c.ExecutionSignerAuthorization, agreement: c.Agreement,
		offerResolver: c.ProviderOfferResolver, timeout: c.Timeout, now: c.Now}, nil
}

// ClaimPaidDemandExecution is the Native Gate. It proves finalized
// buyer acceptance and funding, reconstructs the complete Provider Offer from
// the Quote without a market database, verifies the exact generic Agreement,
// and binds the one-shot execution claim to explicit input/source commitments.
func (g *Gate) ClaimPaidDemandExecution(ctx context.Context, r Request) (Evidence, error) {
	if g == nil || g.paidEscrow == nil || g.offerResolver == nil || ctx == nil || !rawAddress(r.EscrowAddress) ||
		!cellDigest(r.QuoteCommitment) || !shaDigest(r.ExecutionID) || !shaDigest(r.InputDigest) || !shaDigest(r.SourceDigest) ||
		r.InputDigest == r.SourceDigest {
		return Evidence{}, errors.New("invalid Paid Demand execution claim")
	}
	call, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	escrow, found, err := g.paidEscrow.ResolveFinalizedV2(call, r.EscrowAddress)
	if err != nil {
		return Evidence{}, err
	}
	now := g.now().UTC()
	if now.Unix() < 0 || !found || escrow == nil || escrow.State == nil ||
		!validReference(escrow.Reference, nativecore.EscrowV2CodeHash) ||
		escrow.State.Status != nativecore.EscrowStatusFundedV2 || escrow.State.AcceptedAtUnix == 0 ||
		escrow.State.QuoteCommitment != r.QuoteCommitment || escrow.State.ProviderAddress != g.provider ||
		escrow.State.ExecutionDeadline <= uint64(now.Unix()) || escrow.State.RefundAvailableAt <= uint64(now.Unix()) {
		return Evidence{}, errors.New("Paid Demand escrow is not an executable finalized purchase")
	}
	terms := nativecore.EscrowTermsV1{BuyerAddress: escrow.State.BuyerAddress, ProviderAddress: escrow.State.ProviderAddress,
		FundingDeadline: escrow.State.FundingDeadline, RefundAvailableAt: escrow.State.RefundAvailableAt}
	acceptanceTime := time.Unix(int64(escrow.State.AcceptedAtUnix), 0).UTC()
	quote, offer, err := paiddemand.VerifyAcceptedQuote(escrow.State.AcceptedQuote, g.agreement, g.network, terms, g.offerResolver, acceptanceTime)
	if err != nil {
		return Evidence{}, err
	}
	p := quote.Terms.Proposal
	if p.ProviderAgentId != g.providerAgent || p.ManifestDigest != g.manifest || p.TransportBindingDigest != g.transport ||
		quote.Terms.ExecutionSignerAuthorization != g.signerAuth || p.MaximumPrice == nil ||
		p.MaximumPrice.AtomicAmount != escrow.State.FundedAtomicAmount || !agreementCommitsExecution(g.agreement,
		g.providerAgent, offer.Binding.BuyerAgentID, r.InputDigest, r.SourceDigest) {
		return Evidence{}, errors.New("Paid Demand Quote or Agreement differs from provider execution policy")
	}
	agentState, err := g.resolveNative(call, g.providerAgent, now)
	if err != nil {
		return Evidence{}, err
	}
	agent := agentState.GetAgent()
	if agent == nil || agent.AgentId != g.providerAgent || agent.Tombstoned {
		return Evidence{}, errors.New("provider Agent is absent or tombstoned")
	}
	capabilityState, err := g.resolveNative(call, p.CapabilityId, now)
	if err != nil {
		return Evidence{}, err
	}
	capability := capabilityState.GetCapability()
	active := capability != nil && capability.CapabilityId == p.CapabilityId && capability.OwnerAgentId == g.providerAgent && !capability.Tombstoned
	if active {
		active = false
		for _, version := range capability.Versions {
			active = active || version != nil && version.Version == p.CapabilityVersion && version.ManifestDigest == g.manifest && !version.Revoked
		}
	}
	if !active {
		return Evidence{}, errors.New("Capability no longer authorizes Paid Demand execution")
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(g.agreement)
	offerDigest, _ := commerce.ProviderOfferDigest(offer)
	evidence := Evidence{NetworkID: g.network.NetworkId, ProviderAgentID: g.providerAgent, ProviderAddress: g.provider,
		CapabilityID: p.CapabilityId, CapabilityVersion: p.CapabilityVersion, ManifestDigest: g.manifest,
		QuoteCommitment: r.QuoteCommitment, EscrowAddress: r.EscrowAddress, EscrowCodeHash: escrow.Reference.ContractCodeHash,
		RegistryCodeHash: g.registryHash, EscrowTransactionHash: escrow.Reference.TransactionHash,
		AgentTransactionHash: agentState.Reference.TransactionHash, CapabilityTransactionHash: capabilityState.Reference.TransactionHash,
		EscrowFinalizedCheckpoint: escrow.Reference.FinalizedCheckpoint, AgentFinalizedCheckpoint: agentState.Reference.FinalizedCheckpoint,
		CapabilityFinalizedCheckpoint: capabilityState.Reference.FinalizedCheckpoint, AgreementBodyDigest: agreementDigest,
		ProviderOfferDigest: offerDigest, AcceptedAtUnix: escrow.State.AcceptedAtUnix}
	if err := g.store.claim(r, evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func agreementCommitsExecution(body commerce.AgentAgreementBody, provider, buyer, inputDigest, sourceDigest string) bool {
	inputExtension := "tos.input." + strings.TrimPrefix(inputDigest, "sha256:")
	sourceExtension := "tos.source." + strings.TrimPrefix(sourceDigest, "sha256:")
	for _, obligation := range body.Obligations {
		if obligation.ObligorAgentID != provider || obligation.BeneficiaryAgentID != buyer {
			continue
		}
		input, source, inputExtensionFound, sourceExtensionFound := false, false, false, false
		for _, digest := range obligation.AttachmentDigests {
			input = input || digest == inputDigest
			source = source || digest == sourceDigest
		}
		for _, extension := range obligation.RequiredExtensions {
			inputExtensionFound = inputExtensionFound || extension == inputExtension
			sourceExtensionFound = sourceExtensionFound || extension == sourceExtension
		}
		if input && source && inputExtensionFound && sourceExtensionFound {
			return true
		}
	}
	return false
}

func (g *Gate) resolveNative(ctx context.Context, objectID string, now time.Time) (*nativev1.NativeStateV1, error) {
	state, found, finalizedAt, err := g.native.ResolveFinalizedState(ctx, objectID, "")
	if err != nil {
		return nil, err
	}
	if !found || state == nil || finalizedAt.IsZero() || finalizedAt.After(now.Add(time.Minute)) ||
		!validReference(state.Reference, g.registryHash) ||
		!cellDigest(state.TvmStateHash) || !proto.Equal(state.Network, g.network) {
		return nil, errors.New("object is not valid finalized Native state")
	}
	return state, nil
}

func validReference(r *nativev1.ChainReference, expectedCodeHash string) bool {
	return r != nil && r.FinalizedCheckpoint > 0 && cellDigest(r.ContractCodeHash) &&
		(expectedCodeHash == "" || r.ContractCodeHash == expectedCodeHash) && shaDigest(r.TransactionHash)
}

func validDigest(v, prefix string) bool {
	if len(v) != len(prefix)+64 || !strings.HasPrefix(v, prefix) || v != strings.ToLower(v) {
		return false
	}
	b, err := hex.DecodeString(v[len(prefix):])
	return err == nil && !bytes.Equal(b, make([]byte, 32))
}

func shaDigest(v string) bool  { return validDigest(v, "sha256:") }
func cellDigest(v string) bool { return validDigest(v, "tvm-cell-sha256:") }
func agentID(v string) bool {
	return len(v) == 70 && strings.HasPrefix(v, "agent_") && validDigest("sha256:"+v[6:], "sha256:")
}
func rawAddress(v string) bool {
	wc, id, ok := strings.Cut(v, ":")
	return ok && wc == "0" && len(id) == 64 && validDigest("sha256:"+id, "sha256:")
}
