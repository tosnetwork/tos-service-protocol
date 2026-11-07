package toschain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Service Actor transaction kinds.
const (
	ActorTxCall     = "call"
	ActorTxRespond  = "respond"
	ActorTxExpire   = "expire"
	ActorTxClaim    = "claim_refund"
	ActorTxSweep    = "sweep"
	ActorTxOwner    = "owner_operation"
	ActorTxTransfer = "transfer"
	ActorTxBounced  = "bounced"
	ActorTxExternal = "external"
	ActorTxNoInput  = "no_input"
	ActorTxFailed   = "failed"
	ActorTxSystem   = "system"
)

// ActorPayout is one internal out-message of a successful transaction.
type ActorPayout struct {
	Destination string `json:"destination"`
	AmountNano  string `json:"amount_nanotos"`
	Bounce      bool   `json:"bounce"`
	EmptyBody   bool   `json:"empty_body"`
}

// ActorTransaction is one classified finalized transaction of an actor. It
// is a plain value so that endpoints can be compared by quorum.
type ActorTransaction struct {
	LT        uint64 `json:"lt"`
	Hash      string `json:"hash"`
	Now       uint32 `json:"now"`
	Kind      string `json:"kind"`
	Sender    string `json:"sender,omitempty"`
	ValueNano string `json:"value_nanotos,omitempty"`
	ExitCode  int32  `json:"exit_code"`
	// BodyBOC is the raw inbound body of a failed transaction.
	BodyBOC string `json:"body_boc,omitempty"`
	// Call carries the decoded inbound call body, for a successful call and,
	// when the body is a complete call, for a failed one.
	Call *ActorCallBody `json:"call,omitempty"`
	// Opcode, QueryID, RequestID, ResponseHash, Signed, Destination describe
	// a successful lifecycle message.
	Opcode       uint32        `json:"opcode,omitempty"`
	QueryID      uint64        `json:"query_id,omitempty"`
	RequestID    uint64        `json:"request_id,omitempty"`
	ResponseHash string        `json:"response_hash,omitempty"`
	Signed       bool          `json:"signed,omitempty"`
	Destination  string        `json:"destination,omitempty"`
	Snapshot     *ActorSAR1    `json:"snapshot,omitempty"`
	Payouts      []ActorPayout `json:"payouts,omitempty"`
}

// ActorCallBody is a decoded call body.
type ActorCallBody struct {
	QueryID           uint64 `json:"query_id"`
	RequestHash       string `json:"request_hash"`
	ExpectedTermsHash string `json:"expected_terms_hash"`
}

// ActorSAR1 carries the exact request snapshot body; Decode re-derives the
// typed snapshot from it.
type ActorSAR1 struct {
	BodyBOC string `json:"body_boc"`
}

// Decode returns the typed request snapshot.
func (s *ActorSAR1) Decode() (nativecore.ServiceActorRequestSnapshotV1, error) {
	if s == nil {
		return nativecore.ServiceActorRequestSnapshotV1{}, errors.New("request snapshot is missing")
	}
	root, err := decodeCellBOC(s.BodyBOC)
	if err != nil {
		return nativecore.ServiceActorRequestSnapshotV1{}, errors.New("invalid request snapshot BOC")
	}
	return nativecore.DecodeServiceActorRequestSnapshot(root)
}

func bocText(value *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(value.ToBOCWithOptions(cell.BOCSerializeOptions{}))
}

// ClassifyActorTransactions classifies a finalized history of the actor
// account, newest first. Failed transactions never need a decodable body; a
// successful lifecycle transaction must decode strictly, and a successful call
// must carry exactly one request snapshot sent by the actor to addr_none.
func ClassifyActorTransactions(actor string, history []tlb.Transaction) ([]ActorTransaction, error) {
	actorAccount, err := hex.DecodeString(strings.TrimPrefix(actor, "0:"))
	if err != nil || len(actorAccount) != 32 || !strings.HasPrefix(actor, "0:") {
		return nil, errors.New("invalid actor address")
	}
	result := make([]ActorTransaction, 0, len(history))
	for index := range history {
		transaction := &history[index]
		if !bytes.Equal(transaction.AccountAddr, actorAccount) {
			return nil, errors.New("history contains another account's transaction")
		}
		classified, err := classifyActorTransaction(actor, transaction)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", transaction.LT, err)
		}
		result = append(result, classified)
	}
	return result, nil
}

func classifyActorTransaction(actor string, transaction *tlb.Transaction) (ActorTransaction, error) {
	result := ActorTransaction{LT: transaction.LT, Hash: hex.EncodeToString(transaction.Hash), Now: transaction.Now}
	description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
	if !ordinary {
		result.Kind = ActorTxSystem
		return result, nil
	}
	success := false
	if compute, vm := description.ComputePhase.Phase.(tlb.ComputePhaseVM); vm {
		success = compute.Success && !description.Aborted
		result.ExitCode = compute.Details.ExitCode
	}
	if transaction.IO.In == nil {
		result.Kind = ActorTxNoInput
		return result, nil
	}
	if transaction.IO.In.MsgType != tlb.MsgTypeInternal {
		result.Kind = ActorTxExternal
		return result, nil
	}
	in := transaction.IO.In.AsInternal()
	if in.SrcAddr == nil || in.SrcAddr.Type() != address.StdAddress {
		return result, errors.New("inbound message has no internal sender")
	}
	result.Sender = in.SrcAddr.StringRaw()
	result.ValueNano = in.Amount.Nano().String()
	if in.Bounced {
		result.Kind = ActorTxBounced
		return result, nil
	}
	body := in.Body
	if body == nil {
		body = cell.BeginCell().EndCell()
	}
	if !success {
		result.Kind = ActorTxFailed
		result.BodyBOC = bocText(body)
		if decoded, err := nativecore.DecodeServiceActorInbound(body); err == nil && decoded.Opcode == nativecore.ServiceActorCallOpcode {
			result.Call = callBody(decoded)
		}
		return result, nil
	}
	if body.BitsSize() == 0 && body.RefsNum() == 0 {
		result.Kind = ActorTxTransfer
		return result, nil
	}
	decoded, err := nativecore.DecodeServiceActorInbound(body)
	if err != nil {
		return result, fmt.Errorf("successful transaction has an undecodable body: %w", err)
	}
	result.Opcode, result.QueryID = decoded.Opcode, decoded.QueryID
	payouts, snapshots, err := actorOutputs(actor, transaction)
	if err != nil {
		return result, err
	}
	result.Payouts = payouts
	switch decoded.Opcode {
	case nativecore.ServiceActorCallOpcode:
		result.Kind, result.Call = ActorTxCall, callBody(decoded)
		if len(snapshots) != 1 {
			return result, fmt.Errorf("successful call emitted %d request snapshots, not one", len(snapshots))
		}
		result.Snapshot = &ActorSAR1{BodyBOC: bocText(snapshots[0])}
		if _, err := result.Snapshot.Decode(); err != nil {
			return result, fmt.Errorf("successful call emitted a malformed request snapshot: %w", err)
		}
		return result, nil
	case nativecore.ServiceActorRespondOpcode:
		result.Kind, result.RequestID = ActorTxRespond, decoded.RequestID
		result.ResponseHash, result.Signed = hex.EncodeToString(decoded.ResponseHash[:]), decoded.Signed
	case nativecore.ServiceActorExpireOpcode:
		result.Kind, result.RequestID = ActorTxExpire, decoded.RequestID
	case nativecore.ServiceActorClaimRefundOpcode:
		result.Kind, result.RequestID = ActorTxClaim, decoded.RequestID
		destination, ok := decoded.Destination.RawStandard()
		if !ok {
			destination = "raw:" + hex.EncodeToString(decoded.Destination.Bits)
		}
		result.Destination = destination
	case nativecore.ServiceActorSweepOpcode:
		result.Kind, result.RequestID = ActorTxSweep, decoded.RequestID
	default:
		result.Kind = ActorTxOwner
	}
	if len(snapshots) != 0 {
		return result, errors.New("only a call emits a request snapshot")
	}
	return result, nil
}

func callBody(decoded nativecore.ServiceActorInboundV1) *ActorCallBody {
	return &ActorCallBody{QueryID: decoded.QueryID, RequestHash: hex.EncodeToString(decoded.RequestHash[:]),
		ExpectedTermsHash: hex.EncodeToString(decoded.ExpectedTermsHash[:])}
}

// actorOutputs splits the out-messages into internal payouts and request
// snapshot bodies: an external out-message from the actor to addr_none. Any
// other external out-message is refused.
func actorOutputs(actor string, transaction *tlb.Transaction) ([]ActorPayout, []*cell.Cell, error) {
	if transaction.IO.Out == nil {
		if transaction.OutMsgCount != 0 {
			return nil, nil, errors.New("out-message count without out-messages")
		}
		return nil, nil, nil
	}
	messages, err := transaction.IO.Out.ToSlice()
	if err != nil || len(messages) != int(transaction.OutMsgCount) {
		return nil, nil, errors.New("invalid out-message list")
	}
	var payouts []ActorPayout
	var snapshots []*cell.Cell
	for _, message := range messages {
		switch message.MsgType {
		case tlb.MsgTypeInternal:
			out := message.AsInternal()
			if out.DstAddr == nil {
				return nil, nil, errors.New("internal out-message has no destination")
			}
			empty := out.Body == nil || out.Body.BitsSize() == 0 && out.Body.RefsNum() == 0
			payouts = append(payouts, ActorPayout{Destination: out.DstAddr.StringRaw(), AmountNano: out.Amount.Nano().String(),
				Bounce: out.Bounce, EmptyBody: empty})
		case tlb.MsgTypeExternalOut:
			out := message.AsExternalOut()
			if out.SrcAddr == nil || out.SrcAddr.StringRaw() != actor || (out.DstAddr != nil && !out.DstAddr.IsAddrNone()) ||
				out.StateInit != nil || out.Body == nil {
				return nil, nil, errors.New("external out-message is not a request snapshot from the actor to addr_none")
			}
			snapshots = append(snapshots, out.Body)
		default:
			return nil, nil, errors.New("unexpected out-message type")
		}
	}
	return payouts, snapshots, nil
}
