package nativecore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// ContractCellSender is a fee-paying transport boundary. Implementations must
// not interpret or rewrite signed Native semantics.
type ContractCellSender interface {
	SendContractCell(context.Context, string, uint64, string, string) error
}

type RelayStateResolver interface {
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
	ResolveFinalizedState(context.Context, string, string) (*nativev1.NativeStateV1, bool, time.Time, error)
}

const (
	MinimumRelayFundingNanoTOS uint64 = 200_000_000
	MaximumRelayFundingNanoTOS uint64 = 100_000_000_000
	MinimumRecoveryRelaySafety        = 5 * time.Minute
	MaximumRecoveryRelaySafety        = 24 * time.Hour
)

type Relayer struct {
	Locator  *Locator
	Sender   ContractCellSender
	Verifier mldsa44.Verifier
	// FundingNanoTOS is attached to every broadcast.
	FundingNanoTOS uint64
	Journal        RelayJournal
	Resolver       RelayStateResolver
	Limits         RelaySpendLimits
	RecoverySafety time.Duration
	Now            func() time.Time
}

func (r *Relayer) configured() bool {
	return r != nil && r.Locator != nil && r.Sender != nil && r.Verifier != nil && r.Journal != nil && r.Resolver != nil &&
		r.FundingNanoTOS >= MinimumRelayFundingNanoTOS && r.FundingNanoTOS <= MaximumRelayFundingNanoTOS &&
		r.Limits.permitsSingle(r.FundingNanoTOS) && validRecoverySafety(r.RecoverySafety)
}

func (r *Relayer) CheckReady(ctx context.Context) error {
	if !r.configured() {
		return errors.New("simplified Native relayer is not configured")
	}
	if ready, ok := r.Sender.(interface{ CheckContractCellReady(context.Context) error }); ok {
		return ready.CheckContractCellReady(ctx)
	}
	return nil
}

func (r *Relayer) Submit(ctx context.Context, submission *nativev1.SignedNativeActionV1, requestID uint64) (string, error) {
	if requestID == 0 {
		return "", errors.New("Native relay request ID must be nonzero")
	}
	return r.submit(ctx, submission, "request:"+strconv.FormatUint(requestID, 10))
}

func (r *Relayer) SubmitIdempotent(ctx context.Context, submission *nativev1.SignedNativeActionV1, idempotencyKey string) (string, error) {
	if idempotencyKey == "" {
		return "", errors.New("Native relay idempotency key must be nonempty")
	}
	return r.submit(ctx, submission, idempotencyKey)
}

func (r *Relayer) submit(ctx context.Context, submission *nativev1.SignedNativeActionV1, idempotencyKey string) (string, error) {
	if !r.configured() || ctx == nil || submission == nil || submission.Action == nil {
		return "", errors.New("simplified Native relayer is not configured")
	}
	built, err := BuildAction(submission.Action)
	if err != nil {
		return "", err
	}
	if submission.Action.TargetContractCodeHash != r.Locator.CodeHash {
		return "", nativeError(ErrWrongContract, "Native action is bound to a different contract code hash")
	}
	if err := validateSignatureShape(built.Kind, submission.CounterpartySignatures); err != nil {
		return "", err
	}
	actionIdentity := canonicalRelayActionIdentity(submission.Action, built.HashString)
	stateSlotIdentity := canonicalRelayStateSlotIdentity(submission.Action)
	queryID := relayQueryID(actionIdentity)
	bodyBuilder, opcode := MessageBody, uint64(opSubmit)
	destinationID := submission.Action.TargetObjectId
	stateInit := ""
	switch payload := submission.Action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		// Agent registration deploys the target directly.
	case *nativev1.NativeActionV1_RegisterCapability:
		destinationID = payload.RegisterCapability.OwnerAgentId
		bodyBuilder, opcode = AgentAuthorizationBody, opAuthorizeCapability
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		destinationID = payload.AddCapabilityVersion.OwnerAgentId
		bodyBuilder, opcode = AgentAuthorizationBody, opAuthorizeCapability
	case *nativev1.NativeActionV1_TransferCapability:
		destinationID = payload.TransferCapability.CurrentOwnerAgentId
		bodyBuilder, opcode = AgentAuthorizationBody, opAuthorizeCapability
	case *nativev1.NativeActionV1_RevokeCapability:
		destinationID = payload.RevokeCapability.OwnerAgentId
		bodyBuilder, opcode = AgentAuthorizationBody, opAuthorizeCapability
	}
	body, err := bodyBuilder(built, submission.AuthoritySignatures, submission.CounterpartySignatures, queryID)
	if err != nil {
		return "", err
	}
	identity, err := r.Locator.Locate(destinationID)
	if err != nil {
		return "", err
	}
	if built.Kind == KindRegisterAgent {
		stateInit = identity.StateInitBOC
	}
	bodyRaw := body.ToBOC()
	stateInitRaw := []byte{}
	if stateInit != "" {
		stateInitRaw, err = base64.StdEncoding.DecodeString(stateInit)
		if err != nil {
			return "", errors.New("invalid Native relay StateInit encoding")
		}
	}
	intent := RelayIntent{
		ActionHash: built.HashString, Destination: identity.Address, QueryID: queryID,
		BodyHash: relayPayloadHash(bodyRaw), StateInitHash: relayPayloadHash(stateInitRaw),
		FundingNanoTOS: r.FundingNanoTOS, StateSlotIdentity: stateSlotIdentity,
		TargetObjectID: submission.Action.TargetObjectId,
	}
	found, complete, existing, err := r.Journal.Lookup(idempotencyKey, actionIdentity, intent)
	if err != nil {
		return "", err
	}
	if found {
		return r.resolveRecordedIntent(ctx, submission.Action.TargetObjectId, actionIdentity, intent, complete, existing)
	}
	targetState, err := r.preflightTargetTransition(ctx, submission.Action, built)
	if err != nil {
		return "", err
	}
	// Authority is resolved once, from finalized state, and every signature
	// set considered for this attempt is checked against that one snapshot.
	authority, err := r.resolveAuthority(ctx, submission.Action, built, targetState)
	if err != nil {
		return "", err
	}
	if err := r.checkAuthority(ctx, submission.Action, built, authority,
		submission.AuthoritySignatures, submission.CounterpartySignatures); err != nil {
		return "", err
	}
	complete, existing, err = r.Journal.Begin(idempotencyKey, actionIdentity, intent, bodyRaw, r.Limits, r.now())
	if err != nil {
		return "", err
	}
	if complete {
		return existing, nil
	}
	if existing != "" {
		return r.resolveRecordedIntent(ctx, submission.Action.TargetObjectId, actionIdentity, intent, false, existing)
	}
	recordedBody, prepared, err := r.Journal.RecordedBody(actionIdentity, intent)
	if err != nil {
		return "", err
	}
	// A prepared slot was never broadcast. Its recorded body is kept while
	// its signatures still authorize the action against the authority just
	// resolved; when they no longer do and this submission's signatures do,
	// this submission's body replaces it in the same atomic step that takes
	// the broadcast lease. A slot that is broadcasting or complete is never
	// refreshed.
	var replacement []byte
	if prepared && !bytes.Equal(recordedBody, bodyRaw) {
		stale, err := r.recordedBodyIsStale(ctx, submission.Action, built, authority, recordedBody, opcode, queryID)
		if err != nil {
			return "", err
		}
		if stale {
			replacement = bodyRaw
		}
	}
	acquired, complete, sendBody, err := r.Journal.AcquireBroadcastLease(actionIdentity, intent, relayPayloadHash(recordedBody), replacement)
	if err != nil {
		return "", err
	}
	if complete {
		return built.HashString, nil
	}
	if !acquired {
		return r.resolveRecordedIntent(ctx, submission.Action.TargetObjectId, actionIdentity, intent, false, built.HashString)
	}
	// Broadcast the body the lease handed out: the slot's recorded body, or
	// this submission's body when it replaced a stale one. Either authorizes
	// the same single transition.
	if err := r.Sender.SendContractCell(ctx, identity.Address, r.FundingNanoTOS,
		base64.StdEncoding.EncodeToString(sendBody), stateInit); err != nil {
		return "", err
	}
	if err := r.Journal.Complete(actionIdentity, intent); err != nil {
		return "", err
	}
	return built.HashString, nil
}

func validateSignatureShape(kind Kind, counterparty []*nativev1.SignatureV1) error {
	switch kind {
	case KindUpdateAgentPolicy, KindInitiateRecovery, KindTransferCapability:
		if len(counterparty) == 0 {
			return nativeError(ErrBadSignature, "Native action requires counterparty signatures")
		}
	default:
		if len(counterparty) != 0 {
			return nativeError(ErrBadSignature, "Native action forbids counterparty signatures")
		}
	}
	return nil
}

func canonicalRelayActionIdentity(action *nativev1.NativeActionV1, actionHash string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("tos.service.relay.action.v1"))
	fields := []string{action.Protocol, action.Network.NetworkId, action.Network.GenesisRootHash,
		action.Network.GenesisFileHash, action.TargetContractCodeHash, actionHash}
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// relayQueryID derives the outbound query ID from the canonical action
// identity, so a caller cannot change the body by changing its request key.
func relayQueryID(actionIdentity string) uint64 {
	digest := sha256.Sum256([]byte(actionIdentity))
	queryID := binary.BigEndian.Uint64(digest[:8])
	if queryID == 0 {
		queryID = 1
	}
	return queryID
}

func canonicalRelayStateSlotIdentity(action *nativev1.NativeActionV1) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("tos.service.relay.state-slot.v1"))
	fields := []string{action.Protocol, action.Network.NetworkId, action.Network.GenesisRootHash,
		action.Network.GenesisFileHash, action.TargetContractCodeHash, action.TargetObjectId,
		strconv.FormatUint(action.Generation, 10), strconv.FormatUint(action.Sequence, 10), action.PredecessorTvmStateHash}
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func relayPayloadHash(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (r *Relayer) resolveRecordedIntent(ctx context.Context, objectID, actionIdentity string, intent RelayIntent, complete bool, existing string) (string, error) {
	if complete {
		return existing, nil
	}
	state, found, err := r.Resolver.ResolveState(ctx, objectID, "")
	if err == nil && found {
		last := ""
		if state.GetAgent() != nil {
			last = state.GetAgent().LastActionHash
		} else if state.GetCapability() != nil {
			last = state.GetCapability().LastActionHash
		}
		if last == intent.ActionHash {
			if err := r.Journal.Complete(actionIdentity, intent); err != nil {
				return "", err
			}
			return intent.ActionHash, nil
		}
	}
	return "", errors.New("Native relay outcome is ambiguous; refusing to rebroadcast")
}

// errAuthorityUnavailable reports that the finalized authority an action
// needs could not be resolved. It is never a decision about signatures.
var errAuthorityUnavailable = errors.New("finalized Native authority is unavailable")

// resolvedAuthority is the finalized authority one relay attempt checks every
// signature set against.
type resolvedAuthority struct {
	policy         *nativev1.ControllerPolicyV1
	purpose        uint32
	recovery       bool
	newOwnerPolicy *nativev1.ControllerPolicyV1
}

// resolveAuthority resolves, from finalized state only, the policies that
// authorize an action. A registration carries its own policy. Failure to
// resolve is errAuthorityUnavailable, without a protocol code.
func (r *Relayer) resolveAuthority(ctx context.Context, action *nativev1.NativeActionV1, built BuiltAction, targetState *nativev1.NativeStateV1) (resolvedAuthority, error) {
	if built.Kind == KindRegisterAgent {
		if action.GetRegisterAgent() == nil {
			return resolvedAuthority{}, nativeError(ErrBadAction, "missing Agent registration policy")
		}
		return resolvedAuthority{}, nil
	}
	authorityAgent := action.TargetObjectId
	resolved := resolvedAuthority{purpose: PurposeAgentControl}
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_DelegateAgent:
		resolved.purpose = PurposeDelegation
	case *nativev1.NativeActionV1_InitiateRecovery, *nativev1.NativeActionV1_CompleteRecovery:
		resolved.purpose, resolved.recovery = PurposeRecovery, true
	case *nativev1.NativeActionV1_RegisterCapability:
		authorityAgent, resolved.purpose = payload.RegisterCapability.OwnerAgentId, PurposeCapabilityControl
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		authorityAgent, resolved.purpose = payload.AddCapabilityVersion.OwnerAgentId, PurposeCapabilityControl
	case *nativev1.NativeActionV1_TransferCapability:
		authorityAgent, resolved.purpose = payload.TransferCapability.CurrentOwnerAgentId, PurposeCapabilityControl
	case *nativev1.NativeActionV1_RevokeCapability:
		authorityAgent, resolved.purpose = payload.RevokeCapability.OwnerAgentId, PurposeCapabilityControl
	}
	if authorityAgent == action.TargetObjectId {
		agent := targetState.GetAgent()
		if agent == nil || agent.AgentId != authorityAgent || agent.Tombstoned || agent.Policy == nil {
			return resolvedAuthority{}, errAuthorityUnavailable
		}
		resolved.policy = agent.Policy
	} else {
		policy, err := r.finalizedAgentPolicy(ctx, authorityAgent)
		if err != nil {
			return resolvedAuthority{}, err
		}
		resolved.policy = policy
	}
	if transfer := action.GetTransferCapability(); transfer != nil {
		policy, err := r.finalizedAgentPolicy(ctx, transfer.NewOwnerAgentId)
		if err != nil {
			return resolvedAuthority{}, err
		}
		resolved.newOwnerPolicy = policy
	}
	return resolved, nil
}

// finalizedAgentPolicy resolves a live Agent's policy from finalized state.
func (r *Relayer) finalizedAgentPolicy(ctx context.Context, agentID string) (*nativev1.ControllerPolicyV1, error) {
	state, found, finalizedAt, err := r.Resolver.ResolveFinalizedState(ctx, agentID, "")
	if err != nil || !found || state == nil || finalizedAt.IsZero() || finalizedAt.Unix() < 0 {
		return nil, errAuthorityUnavailable
	}
	agent := state.GetAgent()
	if agent == nil || agent.AgentId != agentID || agent.Tombstoned || agent.Policy == nil {
		return nil, errAuthorityUnavailable
	}
	return agent.Policy, nil
}

// checkAuthority checks one pair of signature sets against resolved
// authority, as the Registry would: registration possession and consent,
// or threshold signatures of the authority policy plus, where the action
// needs it, possession of the policy being installed or the new owner's
// consent.
func (r *Relayer) checkAuthority(ctx context.Context, action *nativev1.NativeActionV1, built BuiltAction, resolved resolvedAuthority,
	authority, counterparty []*nativev1.SignatureV1) error {
	if built.Kind == KindRegisterAgent {
		policy := action.GetRegisterAgent().GetInitialPolicy()
		// Possession proves every controller signed; consent is then the
		// policy's Agent-control weight, as the Registry computes it.
		if err := VerifyPolicyPossession(ctx, r.Verifier, policy, authority, built); err != nil {
			return err
		}
		return VerifyRegistrationConsent(policy)
	}
	if err := VerifySignatures(ctx, r.Verifier, resolved.policy, authority, resolved.purpose, resolved.recovery, built); err != nil {
		return err
	}
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_UpdateAgentPolicy:
		return VerifyPolicyPossession(ctx, r.Verifier, payload.UpdateAgentPolicy.NewPolicy, counterparty, built)
	case *nativev1.NativeActionV1_InitiateRecovery:
		return VerifyPolicyPossession(ctx, r.Verifier, payload.InitiateRecovery.NewPolicy, counterparty, built)
	case *nativev1.NativeActionV1_TransferCapability:
		return VerifySignatures(ctx, r.Verifier, resolved.newOwnerPolicy, counterparty, PurposeCapabilityControl, false, built)
	}
	return nil
}

// recordedBodyIsStale reports whether a prepared slot's recorded body no
// longer authorizes the action against the authority resolved for this
// attempt. Only a protocol refusal of its signatures makes it stale; a body
// that does not decode, or a verifier that cannot answer, fails closed and
// leaves the slot unchanged.
func (r *Relayer) recordedBodyIsStale(ctx context.Context, action *nativev1.NativeActionV1, built BuiltAction, resolved resolvedAuthority,
	recorded []byte, opcode, queryID uint64) (bool, error) {
	authority, counterparty, err := decodeSubmissionBody(recorded, built, opcode, queryID)
	if err != nil {
		return false, fmt.Errorf("recorded Native relay body cannot be checked: %w", err)
	}
	err = r.checkAuthority(ctx, action, built, resolved, authority, counterparty)
	if err == nil {
		return false, nil
	}
	if code, ok := ErrorCodeOf(err); ok {
		switch code {
		case ErrBadPolicy, ErrBadSignature, ErrThreshold, ErrDuplicateSignature:
			return true, nil
		}
	}
	return false, fmt.Errorf("recorded Native relay body cannot be checked: %w", err)
}

func (r *Relayer) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func validRecoverySafety(value time.Duration) bool {
	return value >= MinimumRecoveryRelaySafety && value <= MaximumRecoveryRelaySafety && value%time.Second == 0
}

func (r *Relayer) preflightTargetTransition(ctx context.Context, action *nativev1.NativeActionV1, built BuiltAction) (*nativev1.NativeStateV1, error) {
	registration := built.Kind == KindRegisterAgent || built.Kind == KindRegisterCapability
	expected := action.PredecessorTvmStateHash
	if registration {
		expected = ""
	}
	state, found, finalizedAt, err := r.Resolver.ResolveFinalizedState(ctx, action.TargetObjectId, expected)
	if err != nil || finalizedAt.IsZero() || finalizedAt.Unix() < 0 {
		return nil, nativeError(ErrBadTransition, "finalized target state is unavailable")
	}
	if registration {
		if found {
			return nil, nativeError(ErrBadTransition, "Native registration target already exists")
		}
		return nil, nil
	}
	if !found || state == nil || state.TvmStateHash != action.PredecessorTvmStateHash {
		return nil, nativeError(ErrBadPredecessor, "finalized target predecessor is unavailable or stale")
	}
	generationReset := built.Kind == KindCompleteRecovery || built.Kind == KindTransferCapability
	validateOrdering := func(generation, sequence uint64) error {
		if generationReset {
			if generation == math.MaxUint64 || action.Generation != generation+1 || action.Sequence != 1 {
				return nativeError(ErrBadSequence, "Native generation reset is not the exact next state slot")
			}
		} else if sequence == math.MaxUint64 || action.Generation != generation || action.Sequence != sequence+1 {
			return nativeError(ErrBadSequence, "Native mutation is not the exact next state slot")
		}
		return nil
	}
	if built.TargetKind == 1 {
		agent := state.GetAgent()
		if agent == nil || agent.AgentId != action.TargetObjectId {
			return nil, nativeError(ErrBadTransition, "finalized target is not the requested Agent")
		}
		if agent.Tombstoned {
			return nil, nativeError(ErrTombstoned, "Agent is terminal")
		}
		if err := validateOrdering(agent.Generation, agent.Sequence); err != nil {
			return nil, err
		}
		switch payload := action.Payload.(type) {
		case *nativev1.NativeActionV1_DelegateAgent:
			for _, digest := range agent.DelegationDigests {
				if digest == payload.DelegateAgent.DelegationDigest {
					return nil, nativeError(ErrBadTransition, "Agent delegation already exists")
				}
			}
		case *nativev1.NativeActionV1_InitiateRecovery:
			chainTime := uint64(finalizedAt.Unix())
			safetySeconds := uint64(r.RecoverySafety / time.Second)
			if agent.Policy == nil || agent.Policy.RecoveryTimelockSeconds > math.MaxUint64-chainTime ||
				safetySeconds > math.MaxUint64-chainTime-agent.Policy.RecoveryTimelockSeconds ||
				payload.InitiateRecovery.ExecuteAfterUnixSeconds < chainTime+agent.Policy.RecoveryTimelockSeconds+safetySeconds {
				return nil, nativeError(ErrTimelock, "Agent recovery execution time is below the live policy timelock")
			}
		case *nativev1.NativeActionV1_CompleteRecovery:
			if agent.RecoveryPolicy == nil || agent.RecoveryInitiationActionHash != payload.CompleteRecovery.InitiationActionHash {
				return nil, nativeError(ErrBadTransition, "Agent recovery is absent or superseded")
			}
			if agent.RecoveryExecuteAfterUnixSeconds > uint64(finalizedAt.Unix()) {
				return nil, nativeError(ErrTimelock, "Agent recovery timelock has not elapsed")
			}
		}
		return state, nil
	}
	capability := state.GetCapability()
	if capability == nil || capability.CapabilityId != action.TargetObjectId {
		return nil, nativeError(ErrBadTransition, "finalized target is not the requested Capability")
	}
	if capability.Tombstoned {
		return nil, nativeError(ErrTombstoned, "Capability is terminal")
	}
	if err := validateOrdering(capability.Generation, capability.Sequence); err != nil {
		return nil, err
	}
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		if payload.AddCapabilityVersion.OwnerAgentId != capability.OwnerAgentId {
			return nil, nativeError(ErrBadTransition, "Capability owner does not match finalized state")
		}
		for _, version := range capability.Versions {
			if version == nil {
				return nil, nativeError(ErrBadTransition, "finalized Capability version state is invalid")
			}
			if version.Version == payload.AddCapabilityVersion.Version.Version {
				return nil, nativeError(ErrImmutableVersion, "Capability version already exists")
			}
		}
	case *nativev1.NativeActionV1_TransferCapability:
		if payload.TransferCapability.CurrentOwnerAgentId != capability.OwnerAgentId || payload.TransferCapability.NewOwnerAgentId == capability.OwnerAgentId {
			return nil, nativeError(ErrBadTransition, "Capability transfer owner does not match finalized state")
		}
	case *nativev1.NativeActionV1_RevokeCapability:
		if payload.RevokeCapability.OwnerAgentId != capability.OwnerAgentId {
			return nil, nativeError(ErrBadTransition, "Capability owner does not match finalized state")
		}
		if payload.RevokeCapability.Version != "" {
			foundVersion := false
			for _, version := range capability.Versions {
				if version == nil {
					return nil, nativeError(ErrBadTransition, "finalized Capability version state is invalid")
				}
				if version.Version == payload.RevokeCapability.Version {
					foundVersion = true
					if version.Revoked {
						return nil, nativeError(ErrImmutableVersion, "Capability version is already revoked")
					}
				}
			}
			if !foundVersion {
				return nil, nativeError(ErrImmutableVersion, "Capability version does not exist")
			}
		}
	default:
		return nil, nativeError(ErrBadTransition, "Agent action cannot target Capability state")
	}
	return state, nil
}
