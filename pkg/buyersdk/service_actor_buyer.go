// Package buyersdk discovers, verifies and calls Service Actors from
// quorum-finalized state. Gateways remain transport and discovery helpers
// only: every value the buyer commits to is checked against one finalized
// checkpoint before the call, and the call's result is read back from the
// finalized call transaction and its request snapshot.
package buyersdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactorindex"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// ServiceActorSession is one finalized checkpoint with the getters the
// buyer cross-checks.
type ServiceActorSession interface {
	serviceactorindex.Session
	GetRequest(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRequestViewV1, error)
	GetRefund(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRefundV1, error)
}

// ServiceActorReader opens buyer sessions.
type ServiceActorReader interface {
	BeginBuyerSession(ctx context.Context) (ServiceActorSession, error)
}

type chainBuyerReader struct{ reader *toschain.ServiceActorReader }

func (c chainBuyerReader) BeginBuyerSession(ctx context.Context) (ServiceActorSession, error) {
	return c.reader.Begin(ctx)
}

// BuyerReaderFromChain adapts a finalized Service Actor reader.
func BuyerReaderFromChain(reader *toschain.ServiceActorReader) ServiceActorReader {
	return chainBuyerReader{reader: reader}
}

type indexReader struct{ reader ServiceActorReader }

func (i indexReader) BeginSession(ctx context.Context) (serviceactorindex.Session, error) {
	return i.reader.BeginBuyerSession(ctx)
}

// ServiceActorBuyerConfig configures a buyer.
type ServiceActorBuyerConfig struct {
	Reader        ServiceActorReader
	Manifests     serviceactor.ManifestSource
	Network       *nativev1.NetworkDomain
	ActorCodeHash string
	BuyerWallet   string
	Sender        ServiceActorSender
	Journal       *ServiceActorJournal
	Limits        ServiceActorLimits
	Now           func() time.Time
	Random        func([]byte) error
}

// ServiceActorBuyer runs discover -> verify -> call -> resolve.
type ServiceActorBuyer struct {
	config    ServiceActorBuyerConfig
	codeHash  [32]byte
	discovery *serviceactorindex.Discovery
}

// NewServiceActorBuyer refuses an incomplete configuration; the actor code
// hash must be pinned to a Service Actor release.
func NewServiceActorBuyer(config ServiceActorBuyerConfig) (*ServiceActorBuyer, error) {
	if config.Reader == nil || config.Manifests == nil || config.Network == nil || config.Sender == nil ||
		config.Journal == nil || !config.Limits.valid() || !isRawAddress(config.BuyerWallet) {
		return nil, errors.New("invalid Service Actor buyer configuration")
	}
	codeHash, err := digestBytes32(config.ActorCodeHash, "tvm-cell-sha256:")
	if err != nil {
		return nil, errors.New("the Service Actor code hash must be pinned as tvm-cell-sha256:<hex>")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	discovery, err := serviceactorindex.NewDiscovery(indexReader{reader: config.Reader}, config.Network, config.Manifests, config.ActorCodeHash)
	if err != nil {
		return nil, err
	}
	return &ServiceActorBuyer{config: config, codeHash: codeHash, discovery: discovery}, nil
}

func digestBytes32(value, prefix string) ([32]byte, error) {
	var out [32]byte
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix || !validHex64(value[len(prefix):]) {
		return out, errors.New("invalid digest")
	}
	raw, _ := hex.DecodeString(value[len(prefix):])
	copy(out[:], raw)
	return out, nil
}

// Discover verifies a Capability version's Service Actor offer for this
// buyer at one finalized checkpoint.
func (b *ServiceActorBuyer) Discover(ctx context.Context, capabilityID, version string) (*serviceactorindex.Offer, error) {
	return b.discovery.DiscoverOffer(ctx, serviceactorindex.Candidate{CapabilityID: capabilityID, Version: version}, b.config.BuyerWallet)
}

// admit runs admission steps 1-8 for a validated package at one fresh
// checkpoint.
func (b *ServiceActorBuyer) admit(ctx context.Context, validated *quoteexchange.Validated) (*serviceactor.Admission, error) {
	session, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := serviceactor.Gather(ctx, session, b.config.Network, b.config.Manifests,
		validated.Proposal.CapabilityId, validated.Proposal.CapabilityVersion)
	if err != nil {
		return nil, err
	}
	return serviceactor.VerifyAdmission(evidence, b.codeHash, &validated.Rail, validated.Proposal, b.config.BuyerWallet)
}

// Prepare validates a Quote Proposal package, runs admission at one fresh
// checkpoint, builds the rail Accepted Quote and the NSR1 request
// commitment, and durably records and reserves the call.
func (b *ServiceActorBuyer) Prepare(ctx context.Context, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1, executionID, inputDigest [32]byte) (CallRecord, error) {
	if request == nil || request.BuyerAddress != b.config.BuyerWallet {
		return CallRecord{}, errors.New("the Quote request does not name this buyer wallet")
	}
	now := b.config.Now()
	validated, err := quoteexchange.Validate(b.config.Network, request, value, now)
	if err != nil {
		return CallRecord{}, err
	}
	if uint64(now.Unix()) >= validated.Proposal.ExpiresAtUnixSeconds {
		return CallRecord{}, errors.New("the Quote has expired")
	}
	admission, err := b.admit(ctx, validated)
	if err != nil {
		return CallRecord{}, err
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(b.config.Network, validated.Proposal)
	if err != nil {
		return CallRecord{}, err
	}
	var quoteHash [32]byte
	copy(quoteHash[:], quote.Hash())
	serviceRequest, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: quoteHash,
		ExecutionID: executionID, InputDigest: inputDigest})
	if err != nil {
		return CallRecord{}, err
	}
	payment, err := nativecore.MinimumServiceActorCallPayment(admission.Policy.PricePerCall, admission.Policy.StorageFee)
	if err != nil {
		return CallRecord{}, err
	}
	queryID, err := b.queryID()
	if err != nil {
		return CallRecord{}, err
	}
	packageBytes, err := proto.Marshal(value)
	if err != nil {
		return CallRecord{}, err
	}
	record := CallRecord{Schema: callRecordSchema, RequestHash: hex.EncodeToString(serviceRequest.Hash()), QueryID: queryID,
		NetworkID: b.config.Network.NetworkId, GenesisRootHash: b.config.Network.GenesisRootHash, GenesisFileHash: b.config.Network.GenesisFileHash,
		BuyerWallet: b.config.BuyerWallet, Actor: admission.Binding.Actor, ActorCodeHash: b.config.ActorCodeHash,
		CapabilityID: validated.Proposal.CapabilityId, CapabilityVersion: validated.Proposal.CapabilityVersion,
		PackageBase64: base64.StdEncoding.EncodeToString(packageBytes), BuyerAddressInReq: request.BuyerAddress,
		AcceptedQuoteBOC: base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})),
		QuoteCommitment:  commitment, ExecutionID: hex.EncodeToString(executionID[:]), InputDigest: hex.EncodeToString(inputDigest[:]),
		TermsHash: hex.EncodeToString(admission.TermsHash[:]), PolicyVersion: admission.Policy.PolicyVersion,
		PriceNanoTOS: admission.Policy.PricePerCall.String(), StorageFeeNanoTOS: admission.Policy.StorageFee.String(),
		AttestorKeyID: mldsa44.KeyIDText(admission.Binding.AttestorKeyID), PaymentNanoTOS: payment.String(),
		ExpiresAtUnix: validated.Proposal.ExpiresAtUnixSeconds, Phase: PhasePrepared, CreatedUnix: now.Unix(), UpdatedUnix: now.Unix()}
	if err := b.config.Journal.Create(record, b.config.Limits, now); err != nil {
		return CallRecord{}, err
	}
	return record, nil
}

func (b *ServiceActorBuyer) queryID() (uint64, error) {
	var raw [8]byte
	for attempt := 0; attempt < 8; attempt++ {
		if err := b.config.Random(raw[:]); err != nil {
			return 0, errors.New("generate call query_id")
		}
		if value := binary.BigEndian.Uint64(raw[:]); value != 0 {
			return value, nil
		}
	}
	return 0, errors.New("generate call query_id")
}

// reconstruct re-derives the validated package and commitments from a
// record and refuses a record whose stored values no longer reproduce.
func (b *ServiceActorBuyer) reconstruct(record CallRecord) (*quoteexchange.Validated, ServiceActorCallIntent, error) {
	var intent ServiceActorCallIntent
	if record.NetworkID != b.config.Network.NetworkId || record.GenesisRootHash != b.config.Network.GenesisRootHash ||
		record.GenesisFileHash != b.config.Network.GenesisFileHash || record.BuyerWallet != b.config.BuyerWallet ||
		record.ActorCodeHash != b.config.ActorCodeHash {
		return nil, intent, errors.New("the journal record belongs to another network, buyer or release")
	}
	raw, err := base64.StdEncoding.DecodeString(record.PackageBase64)
	if err != nil {
		return nil, intent, errors.New("the journal record package does not decode")
	}
	value := &nativev1.QuoteProposalPackageV1{}
	if err := proto.Unmarshal(raw, value); err != nil {
		return nil, intent, errors.New("the journal record package does not decode")
	}
	validated, err := quoteexchange.ValidatePortable(b.config.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: record.CapabilityID, CapabilityVersion: record.CapabilityVersion, BuyerAddress: record.BuyerAddressInReq}, value)
	if err != nil {
		return nil, intent, err
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(b.config.Network, validated.Proposal)
	if err != nil || commitment != record.QuoteCommitment ||
		base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})) != record.AcceptedQuoteBOC {
		return nil, intent, errors.New("the journal record Accepted Quote does not reproduce")
	}
	var quoteHash, executionID, inputDigest, requestHash [32]byte
	copy(quoteHash[:], quote.Hash())
	for target, text := range map[*[32]byte]string{&executionID: record.ExecutionID, &inputDigest: record.InputDigest, &requestHash: record.RequestHash} {
		decoded, err := hex.DecodeString(text)
		if err != nil || len(decoded) != 32 {
			return nil, intent, errors.New("the journal record carries an invalid digest")
		}
		copy(target[:], decoded)
	}
	serviceRequest, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: quoteHash,
		ExecutionID: executionID, InputDigest: inputDigest})
	if err != nil || hex.EncodeToString(serviceRequest.Hash()) != record.RequestHash {
		return nil, intent, errors.New("the journal record request_hash does not reproduce")
	}
	if hex.EncodeToString(validated.Rail.TermsHash[:]) != record.TermsHash || validated.Rail.Actor != record.Actor ||
		validated.Rail.Price.String() != record.PriceNanoTOS || validated.Rail.StorageFee.String() != record.StorageFeeNanoTOS {
		return nil, intent, errors.New("the journal record rail does not reproduce")
	}
	intent = ServiceActorCallIntent{Actor: record.Actor, BuyerWallet: record.BuyerWallet, QueryID: record.QueryID,
		RequestHash: requestHash, ExpectedTermsHash: validated.Rail.TermsHash, Price: validated.Rail.Price, StorageFee: validated.Rail.StorageFee}
	return validated, intent, nil
}

// Call re-verifies a prepared call at a fresh checkpoint, runs the custody
// preflight, durably enters the sending phase and hands the call to custody.
// A call that left the prepared phase is never sent again.
func (b *ServiceActorBuyer) Call(ctx context.Context, requestHash string) (CallRecord, error) {
	record, err := b.config.Journal.Read(requestHash)
	if err != nil {
		return CallRecord{}, err
	}
	if record.Phase != PhasePrepared {
		return record, fmt.Errorf("call %s is %s and is never sent again", requestHash, record.Phase)
	}
	validated, intent, err := b.reconstruct(record)
	if err != nil {
		return record, err
	}
	if uint64(b.config.Now().Unix()) >= record.ExpiresAtUnix {
		return record, errors.New("the Quote has expired")
	}
	if _, err := b.admit(ctx, validated); err != nil {
		return record, err
	}
	if err := b.config.Sender.Preflight(ctx, intent); err != nil {
		return record, err
	}
	record, err = b.config.Journal.Transition(requestHash, []CallPhase{PhasePrepared}, func(r *CallRecord) error {
		r.Phase, r.UpdatedUnix = PhaseSending, b.config.Now().Unix()
		return nil
	})
	if err != nil {
		return record, err
	}
	sendErr := b.config.Sender.SendCall(ctx, intent)
	next := PhaseSubmitted
	switch {
	case errors.Is(sendErr, ErrCallNotStarted):
		next = PhasePrepared
	case sendErr != nil:
		next = PhaseAmbiguous
	}
	updated, err := b.config.Journal.Transition(requestHash, []CallPhase{PhaseSending}, func(r *CallRecord) error {
		r.Phase, r.UpdatedUnix = next, b.config.Now().Unix()
		return nil
	})
	if err != nil {
		return record, err
	}
	return updated, sendErr
}

// RequestReport is a verified view of a call's request at one checkpoint.
type RequestReport struct {
	Checkpoint          uint64                     `json:"checkpoint"`
	Phase               CallPhase                  `json:"phase"`
	Found               bool                       `json:"found"`
	ExitCode            int32                      `json:"exit_code,omitempty"`
	RequestID           *uint64                    `json:"request_id,omitempty"`
	State               serviceactor.RequestState  `json:"state,omitempty"`
	Status              serviceactor.Status        `json:"status,omitempty"`
	RequiredAction      string                     `json:"required_action,omitempty"`
	ResponseDeadline    uint64                     `json:"response_deadline,omitempty"`
	RefundClaimDeadline uint64                     `json:"refund_claim_deadline,omitempty"`
	CallTransaction     *toschain.ActorTxID        `json:"call_transaction,omitempty"`
	Outcome             *toschain.ActorTransaction `json:"outcome,omitempty"`
	ResponseHash        string                     `json:"response_hash,omitempty"`
}

// Resolve reads the call's outcome at one fresh checkpoint: the exactly one
// finalized call transaction from the buyer wallet carrying the record's
// query_id, request_hash and terms hash, verified from that transaction and
// its request snapshot alone, then the request's lifecycle replayed from the
// complete actor history and reconciled with the actor state and getters.
func (b *ServiceActorBuyer) Resolve(ctx context.Context, requestHash string) (*RequestReport, error) {
	record, err := b.config.Journal.Read(requestHash)
	if err != nil {
		return nil, err
	}
	if record.Phase == PhasePrepared || record.Phase == PhaseSending {
		return &RequestReport{Phase: record.Phase}, nil
	}
	validated, intent, err := b.reconstruct(record)
	if err != nil {
		return nil, err
	}
	session, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := serviceactor.Gather(ctx, session, b.config.Network, b.config.Manifests, record.CapabilityID, record.CapabilityVersion)
	if err != nil {
		return nil, err
	}
	if evidence.Actor == nil {
		return nil, errors.New("the Service Actor account is not active at the checkpoint")
	}
	history, err := session.History(ctx, record.Actor, nil)
	if err != nil {
		return nil, err
	}
	if history.Result != toschain.HistoryComplete || history.Head != evidence.Actor.LastTransaction {
		return nil, errors.New("the Service Actor history is not complete at the checkpoint")
	}
	termsHash := hex.EncodeToString(intent.ExpectedTermsHash[:])
	var matches []toschain.ActorTransaction
	for _, transaction := range history.Transactions {
		if transaction.Sender == record.BuyerWallet && transaction.Call != nil && transaction.Call.QueryID == record.QueryID &&
			transaction.Call.RequestHash == record.RequestHash && transaction.Call.ExpectedTermsHash == termsHash &&
			(transaction.Kind == toschain.ActorTxCall || transaction.Kind == toschain.ActorTxFailed) {
			matches = append(matches, transaction)
		}
	}
	report := &RequestReport{Checkpoint: session.Checkpoint(), Phase: record.Phase}
	switch len(matches) {
	case 0:
		return report, nil
	case 1:
	default:
		return nil, errors.New("more than one finalized call carries this request; refusing to choose")
	}
	call := matches[0]
	report.Found = true
	report.CallTransaction = &toschain.ActorTxID{LT: call.LT, Hash: call.Hash}
	if call.Kind == toschain.ActorTxFailed {
		report.ExitCode = call.ExitCode
		updated, err := b.markOutcome(record, PhaseRefused, nil, call)
		if err != nil {
			return nil, err
		}
		report.Phase = updated.Phase
		return report, nil
	}
	existing, err := serviceactor.VerifyExistingRequest(evidence, b.codeHash, &validated.Rail, validated.Proposal,
		record.Actor, call, record.BuyerWallet, intent.RequestHash)
	if err != nil {
		return nil, err
	}
	requests, err := serviceactor.Replay(history.Transactions, evidence.Actor.Data)
	if err != nil {
		return nil, fmt.Errorf("the actor history does not reconcile with its state: %w", err)
	}
	id := existing.Snapshot.RequestID
	request := requests[id]
	if request == nil || request.Call.Hash != call.Hash {
		return nil, errors.New("the replayed history does not hold this call's request")
	}
	if err := b.crossCheckGetters(ctx, session, record.Actor, id, request, evidence.Actor.Data); err != nil {
		return nil, err
	}
	updated, err := b.markOutcome(record, PhaseAdmitted, &id, call)
	if err != nil {
		return nil, err
	}
	report.Phase, report.RequestID, report.State = updated.Phase, &id, request.State
	report.Status, report.RequiredAction = request.StatusAt(session.ChainTime()), request.RequiredAction(session.ChainTime())
	report.ResponseDeadline, report.RefundClaimDeadline = request.Snapshot.ResponseDeadline, request.Snapshot.RefundClaimDeadline
	report.Outcome = request.Terminal
	if request.Terminal != nil && request.Terminal.Kind == toschain.ActorTxRespond {
		report.ResponseHash = request.Terminal.ResponseHash
	}
	return report, nil
}

func (b *ServiceActorBuyer) crossCheckGetters(ctx context.Context, session ServiceActorSession, actor string, id uint64,
	request *serviceactor.Request, data *nativecore.ServiceActorDataV1) error {
	pending, err := session.GetRequest(ctx, actor, id)
	if err != nil {
		return err
	}
	refund, err := session.GetRefund(ctx, actor, id)
	if err != nil {
		return err
	}
	switch request.State {
	case serviceactor.StatePending:
		if refund != nil || !nativecore.SameRequestView(data.Pending[id], pending) {
			return errors.New("get_request differs from the decoded pending entry")
		}
	case serviceactor.StateExpired:
		if pending != nil || !nativecore.SameRefundView(data.Refunds[id], refund) {
			return errors.New("get_refund differs from the decoded refund entry")
		}
	default:
		if pending != nil || refund != nil {
			return errors.New("a resolved request is still live in the getters")
		}
	}
	return nil
}

func (b *ServiceActorBuyer) markOutcome(record CallRecord, phase CallPhase, id *uint64, call toschain.ActorTransaction) (CallRecord, error) {
	if record.Phase == phase {
		return record, nil
	}
	return b.config.Journal.Transition(record.RequestHash, []CallPhase{PhaseSubmitted, PhaseAmbiguous}, func(r *CallRecord) error {
		r.Phase, r.UpdatedUnix, r.RequestID = phase, b.config.Now().Unix(), id
		r.CallTransactionLT, r.CallTransactionHex, r.ExitCode = call.LT, call.Hash, call.ExitCode
		return nil
	})
}
