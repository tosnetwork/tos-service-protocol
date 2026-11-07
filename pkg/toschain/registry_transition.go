package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
)

// ErrRegistryTransitionUnproven reports that the object's finalized history
// at the checkpoint, read completely within the history bound, holds no
// successful transaction applying the requested transition.
var ErrRegistryTransitionUnproven = errors.New("the Native Registry transition is not proven by the object's finalized history")

// RegistryTransitionTx is the finalized transaction of a Registry object's
// account that first applied a tombstone or version revocation.
type RegistryTransitionTx struct {
	LT   uint64 `json:"lt"`
	Hash string `json:"hash"`
	// ActionHash is the applied action's cell hash, sha256:<hex>.
	ActionHash string `json:"action_hash"`
}

type registryTransitionVote struct {
	Found      bool                 `json:"found"`
	Bounded    bool                 `json:"bounded"`
	Transition RegistryTransitionTx `json:"transition"`
	BlockRoot  string               `json:"block_root"`
	BlockFile  string               `json:"block_file"`
}

// RegistryTransition reads the complete finalized history of a Registry
// object's account at the session checkpoint and returns the earliest
// successful transaction that applied the requested transition: a tombstone
// of the object, or (RegistryVersionRevocation) the revocation of version.
//
// The earliest one is the transition itself. The Registry applies an action
// once; the same action cell succeeds again only as an idempotent no-op while
// it is still the object's last action, which is always after it was applied.
// A history the bound cuts short proves nothing, and is reported as
// ErrRegistryTransitionUnproven like a history without the transition.
func (s *ServiceActorSession) RegistryTransition(ctx context.Context, objectID string, kind nativecore.RegistryTransitionKind,
	version string) (*RegistryTransitionTx, error) {
	switch {
	case kind == nativecore.RegistryAgentTombstone && strings.HasPrefix(objectID, "agent_") && version == "":
	case kind == nativecore.RegistryCapabilityTombstone && strings.HasPrefix(objectID, "cap_") && version == "":
	case kind == nativecore.RegistryVersionRevocation && strings.HasPrefix(objectID, "cap_") && version != "":
	default:
		return nil, errors.New("invalid Native Registry transition request")
	}
	identity, err := s.reader.registry.locator.Locate(objectID)
	if err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrBadAction, "invalid Native object", err)
	}
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (registryTransitionVote, error) {
		return readRegistryTransition(ctx, node, identity.Address, s.seqno, s.reader.maxHistory, objectID, version)
	})
	if err != nil {
		return nil, err
	}
	if err := s.pinHashes(vote.BlockRoot, vote.BlockFile); err != nil {
		return nil, err
	}
	if !vote.Found {
		return nil, ErrRegistryTransitionUnproven
	}
	transition := vote.Transition
	return &transition, nil
}

// readRegistryTransition is one endpoint's view: the account's last
// transaction at the checkpoint, the complete history behind it, and the
// earliest matching transition in it.
func readRegistryTransition(ctx context.Context, node *rpcNode, address string, seqno uint64, bound int, objectID string,
	version string) (registryTransitionVote, error) {
	last, root, file, err := finalizedActorLastTransaction(ctx, node, address, seqno)
	if err != nil {
		return registryTransitionVote{}, err
	}
	history, _, err := walkActorHistory(ctx, node, address, last, nil, bound)
	if errors.Is(err, ErrHistoryBoundExceeded) {
		// An exhausted bound is a finalized fact the endpoints vote on.
		return registryTransitionVote{Bounded: true, BlockRoot: root, BlockFile: file}, nil
	}
	if err != nil {
		return registryTransitionVote{}, err
	}
	transition, found, err := earliestRegistryTransition(address, history, objectID, version)
	if err != nil {
		return registryTransitionVote{}, err
	}
	return registryTransitionVote{Found: found, Transition: transition, BlockRoot: root, BlockFile: file}, nil
}

// earliestRegistryTransition scans a complete newest-first history from its
// oldest transaction and returns the first successful one whose inbound body
// applies a tombstone of objectID or, with version set, the revocation of that
// version. A transaction counts only if it is ordinary, its compute phase
// succeeded, it was not aborted, and its inbound message is an internal,
// non-bounced message carrying the transition.
func earliestRegistryTransition(address string, history []tlb.Transaction, objectID string,
	version string) (RegistryTransitionTx, bool, error) {
	account, err := hex.DecodeString(strings.TrimPrefix(address, "0:"))
	if err != nil || len(account) != 32 || !strings.HasPrefix(address, "0:") {
		return RegistryTransitionTx{}, false, errors.New("invalid Native Registry account address")
	}
	for index := len(history) - 1; index >= 0; index-- {
		transaction := &history[index]
		if !bytes.Equal(transaction.AccountAddr, account) {
			return RegistryTransitionTx{}, false, errors.New("Native Registry history contains another account's transaction")
		}
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		if !ordinary || description.Aborted {
			continue
		}
		compute, vm := description.ComputePhase.Phase.(tlb.ComputePhaseVM)
		if !vm || !compute.Success || transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal {
			continue
		}
		in := transaction.IO.In.AsInternal()
		if in.Bounced || in.Body == nil {
			continue
		}
		// The object prefix and the version, both checked against the
		// request kind on entry, fix the transition kind.
		decoded, err := nativecore.DecodeRegistryTransition(in.Body)
		if err != nil || decoded.ObjectID != objectID || decoded.Version != version {
			continue
		}
		return RegistryTransitionTx{LT: transaction.LT, Hash: hex.EncodeToString(transaction.Hash), ActionHash: decoded.ActionHash}, true, nil
	}
	return RegistryTransitionTx{}, false, nil
}
