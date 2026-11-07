package agentguarantor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// MaxHistoricalAuthorityProofBytes bounds the in-band historical authority
// proof carried by one native authorization.
const MaxHistoricalAuthorityProofBytes = 64 << 10

// DefaultNativeAuthorityReadTimeout bounds the finalized reads behind one
// historical authority resolution when the resolver leaves Timeout unset.
const DefaultNativeAuthorityReadTimeout = 30 * time.Second

var (
	sha256TextPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	cellHashTextPattern    = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	workchainZeroAccountRe = regexp.MustCompile(`^0:[0-9a-f]{64}$`)
)

// FinalizedCheckpointRefV1 names one masterchain block by sequence and its
// root and file hashes.
type FinalizedCheckpointRefV1 struct {
	Sequence uint64 `json:"sequence"`
	RootHash string `json:"root_hash"`
	FileHash string `json:"file_hash"`
}

// FinalizedTransactionRefV1 names one account transaction.
type FinalizedTransactionRefV1 struct {
	LogicalTime     uint64 `json:"logical_time"`
	TransactionHash string `json:"transaction_hash"`
}

// NativeAgentHistoricalAuthorityProofV1 is the canonical CBOR content of
// historical_authority_proof. It only locates finalized TOS state: the
// verifier reads every fact it relies on itself, by quorum, and never takes
// a key, a state or a time from the proof.
//
//   - EffectiveTransaction is the account's last transaction whose block
//     time is at or before validation_time_unix; it produced the NVS1 state
//     that was effective then.
//   - EffectiveCheckpoint is a masterchain block at which that transaction is
//     the account's last transaction, so the account read there is that state.
//   - BoundCheckpoint is a finalized masterchain block whose time is at or
//     after validation_time_unix; the account's history from its last
//     transaction there back to EffectiveTransaction shows that no other
//     transaction happened at or before validation_time_unix.
type NativeAgentHistoricalAuthorityProofV1 struct {
	SchemaVersion        uint16                    `json:"schema_version"`
	NetworkID            string                    `json:"network_id"`
	GenesisRootHash      string                    `json:"genesis_root_hash"`
	GenesisFileHash      string                    `json:"genesis_file_hash"`
	RegistryCodeHash     string                    `json:"registry_code_hash"`
	AgentAccount         string                    `json:"agent_account"`
	EffectiveTransaction FinalizedTransactionRefV1 `json:"effective_transaction"`
	EffectiveCheckpoint  FinalizedCheckpointRefV1  `json:"effective_checkpoint"`
	BoundCheckpoint      FinalizedCheckpointRefV1  `json:"bound_checkpoint"`
}

// EncodeNativeAgentHistoricalAuthorityProofV1 returns the canonical bytes of
// a valid proof.
func EncodeNativeAgentHistoricalAuthorityProofV1(proof NativeAgentHistoricalAuthorityProofV1) ([]byte, error) {
	if err := validateNativeAgentHistoricalAuthorityProofV1(proof); err != nil {
		return nil, err
	}
	encoded, err := codec.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxHistoricalAuthorityProofBytes {
		return nil, errors.New("native historical authority proof exceeds its bound")
	}
	return encoded, nil
}

// DecodeNativeAgentHistoricalAuthorityProofV1 accepts only the exact
// canonical encoding of a valid proof: unknown or missing fields, another
// schema version and non-canonical CBOR fail closed.
func DecodeNativeAgentHistoricalAuthorityProofV1(raw []byte) (NativeAgentHistoricalAuthorityProofV1, error) {
	var proof NativeAgentHistoricalAuthorityProofV1
	if len(raw) == 0 || len(raw) > MaxHistoricalAuthorityProofBytes {
		return proof, errors.New("native historical authority proof has an invalid size")
	}
	if err := codec.Unmarshal(raw, &proof); err != nil {
		return NativeAgentHistoricalAuthorityProofV1{}, fmt.Errorf("native historical authority proof: %w", err)
	}
	reencoded, err := codec.Marshal(proof)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return NativeAgentHistoricalAuthorityProofV1{}, errors.New("native historical authority proof is not exact")
	}
	if err := validateNativeAgentHistoricalAuthorityProofV1(proof); err != nil {
		return NativeAgentHistoricalAuthorityProofV1{}, err
	}
	return proof, nil
}

func validateCheckpointRef(ref FinalizedCheckpointRefV1) bool {
	return ref.Sequence > 0 && sha256TextPattern.MatchString(ref.RootHash) && sha256TextPattern.MatchString(ref.FileHash)
}

func validateTransactionRef(ref FinalizedTransactionRefV1) bool {
	return ref.LogicalTime > 0 && sha256TextPattern.MatchString(ref.TransactionHash)
}

func validateNativeAgentHistoricalAuthorityProofV1(proof NativeAgentHistoricalAuthorityProofV1) error {
	if proof.SchemaVersion != 1 || !validToken(proof.NetworkID, 128) ||
		!sha256TextPattern.MatchString(proof.GenesisRootHash) || !sha256TextPattern.MatchString(proof.GenesisFileHash) ||
		!cellHashTextPattern.MatchString(proof.RegistryCodeHash) || !workchainZeroAccountRe.MatchString(proof.AgentAccount) ||
		!validateTransactionRef(proof.EffectiveTransaction) || !validateCheckpointRef(proof.EffectiveCheckpoint) ||
		!validateCheckpointRef(proof.BoundCheckpoint) || proof.EffectiveCheckpoint.Sequence > proof.BoundCheckpoint.Sequence {
		return errors.New("native historical authority proof is invalid")
	}
	return nil
}

// NativeAgentTransactionV1 is one finalized account transaction as the
// verifier read it.
type NativeAgentTransactionV1 struct {
	Transaction FinalizedTransactionRefV1
	// BlockTimeUnix is the transaction's now: the generation time of the
	// shard block that contains it, written into every transaction of that
	// block.
	BlockTimeUnix uint64
	// Previous is the account's preceding transaction; LogicalTime 0 means
	// none.
	Previous FinalizedTransactionRefV1
}

// NativeAgentHistoryObservationV1 is what a NativeAgentHistoryReader read,
// by quorum, from finalized TOS state at the checkpoints a proof names. It
// carries facts only; CheckNativeAgentHistoricalAuthorityV1 judges them.
type NativeAgentHistoryObservationV1 struct {
	// Network and RegistryCodeHash are what the reader is pinned to.
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	// FinalizedSequence is the quorum-finalized masterchain sequence at the
	// time of the read.
	FinalizedSequence uint64
	// BoundCheckpoint and BoundGenerationUnix come from the quorum-read
	// masterchain block header.
	BoundCheckpoint     FinalizedCheckpointRefV1
	BoundGenerationUnix uint64
	// BoundLastTransaction is the account's last transaction at the bound
	// checkpoint.
	BoundLastTransaction FinalizedTransactionRefV1
	// EffectiveCheckpoint, EffectiveAccount, EffectiveCodeHash and
	// EffectiveLastTransaction come from the account read at the effective
	// checkpoint; State is its NVS1 state decoded by the Native Registry
	// decoder, nil when the account holds no typed state.
	EffectiveCheckpoint      FinalizedCheckpointRefV1
	EffectiveAccount         string
	EffectiveCodeHash        string
	EffectiveLastTransaction NativeAgentTransactionV1
	State                    *nativev1.NativeStateV1
	// History runs newest first from BoundLastTransaction down to and
	// including the effective transaction.
	History []NativeAgentTransactionV1
}

// NativeAgentHistoryReader performs the finalized reads a proof locates.
type NativeAgentHistoryReader interface {
	ReadNativeAgentHistory(ctx context.Context, proof NativeAgentHistoricalAuthorityProofV1,
		subject string) (NativeAgentHistoryObservationV1, error)
}

// NativeAgentAuthorityExpectationV1 is what the verifier itself pins: the
// Agreement's network, the Native Registry code and the account the
// Registry derives for the subject.
type NativeAgentAuthorityExpectationV1 struct {
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	AgentAccount     string
}

func sameNetwork(left, right *nativev1.NetworkDomain) bool {
	return left != nil && right != nil && left.NetworkId == right.NetworkId &&
		left.GenesisRootHash == right.GenesisRootHash && left.GenesisFileHash == right.GenesisFileHash
}

// CheckNativeAgentHistoricalAuthorityV1 proves from an observation that
// keyID was an Agent-control controller of subject, meeting the ordinary
// threshold alone, in the state effective at the signed time, and returns
// the stored ML-DSA-44 key. Every failure is fail-closed.
func CheckNativeAgentHistoricalAuthorityV1(proof NativeAgentHistoricalAuthorityProofV1,
	observation NativeAgentHistoryObservationV1, expected NativeAgentAuthorityExpectationV1,
	subject string, keyID [mldsa44.KeyIDSize]byte, at uint64) ([]byte, error) {
	if err := validateNativeAgentHistoricalAuthorityProofV1(proof); err != nil {
		return nil, err
	}
	if !validUnixTimestampV1(at) {
		return nil, errors.New("native authority validation time is invalid")
	}
	// 1. Network domain: proof, verifier pin and reader pin agree.
	proofNetwork := &nativev1.NetworkDomain{NetworkId: proof.NetworkID, GenesisRootHash: proof.GenesisRootHash,
		GenesisFileHash: proof.GenesisFileHash}
	if !sameNetwork(proofNetwork, expected.Network) || !sameNetwork(observation.Network, expected.Network) {
		return nil, errors.New("native authority proof names another network")
	}
	// 2. The subject's deterministic Registry account at the pinned code.
	if expected.RegistryCodeHash == "" || proof.RegistryCodeHash != expected.RegistryCodeHash ||
		observation.RegistryCodeHash != expected.RegistryCodeHash || observation.EffectiveCodeHash != expected.RegistryCodeHash {
		return nil, errors.New("native authority proof names another registry code")
	}
	if expected.AgentAccount == "" || proof.AgentAccount != expected.AgentAccount ||
		observation.EffectiveAccount != expected.AgentAccount {
		return nil, errors.New("native authority proof names another registry account")
	}
	// 3. The state effective at the signed time.
	if observation.BoundCheckpoint != proof.BoundCheckpoint || observation.EffectiveCheckpoint != proof.EffectiveCheckpoint {
		return nil, errors.New("native authority checkpoints differ from the proof")
	}
	if observation.FinalizedSequence == 0 || proof.BoundCheckpoint.Sequence > observation.FinalizedSequence {
		return nil, errors.New("native authority bound checkpoint is not finalized")
	}
	if observation.BoundGenerationUnix < at {
		return nil, errors.New("native authority bound checkpoint precedes the validation time")
	}
	effective := observation.EffectiveLastTransaction
	if effective.Transaction != proof.EffectiveTransaction {
		return nil, errors.New("native authority effective state was not produced by the proven transaction")
	}
	if effective.BlockTimeUnix == 0 || effective.BlockTimeUnix > at {
		return nil, errors.New("native authority effective transaction is after the validation time")
	}
	history := observation.History
	if len(history) == 0 || history[0].Transaction != observation.BoundLastTransaction ||
		history[len(history)-1] != effective {
		return nil, errors.New("native authority history does not span the bound checkpoint to the effective transaction")
	}
	for index := 0; index+1 < len(history); index++ {
		if history[index].Previous != history[index+1].Transaction ||
			history[index].Transaction.LogicalTime <= history[index+1].Transaction.LogicalTime {
			return nil, errors.New("native authority history is not contiguous")
		}
		// Every transaction newer than the effective one is after the signed
		// time; its content is never examined.
		if history[index].BlockTimeUnix <= at {
			return nil, errors.New("native authority history has a later transaction at or before the validation time")
		}
	}
	// 4. The controller in that state.
	if observation.State == nil {
		return nil, errors.New("native authority account holds no Agent state")
	}
	agent := observation.State.GetAgent()
	if agent == nil || agent.AgentId != subject || agent.Policy == nil {
		return nil, errors.New("native authority state is not the subject Agent")
	}
	if agent.Tombstoned {
		return nil, errors.New("native authority Agent was tombstoned at the validation time")
	}
	keyText := mldsa44.KeyIDText(keyID)
	var controller *nativev1.ControllerV1
	for _, candidate := range agent.Policy.Controllers {
		if candidate != nil && candidate.KeyId == keyText {
			if controller != nil {
				return nil, errors.New("native authority policy names the key twice")
			}
			controller = candidate
		}
	}
	if controller == nil {
		return nil, errors.New("native authority key is not in the effective policy")
	}
	derived, err := mldsa44.KeyID(controller.Mldsa44PublicKey)
	if err != nil || derived != keyID {
		return nil, errors.New("native authority stored key does not derive its key ID")
	}
	if controller.PurposeMask&nativecore.PurposeAgentControl == 0 {
		return nil, errors.New("native authority controller lacks the Agent-control purpose")
	}
	if agent.Policy.Threshold == 0 || controller.Weight < agent.Policy.Threshold {
		return nil, errors.New("native authority controller alone does not reach the policy threshold")
	}
	return append([]byte(nil), controller.Mldsa44PublicKey...), nil
}

// NativeAgentAuthorityResolverV1 resolves native ML-DSA-44 Agent keys from
// the historical authority proof by reading finalized TOS state through
// Reader. Locator pins the network and Registry code; it must be configured
// for the Agreement's network. Signatures verifies ML-DSA-44.
type NativeAgentAuthorityResolverV1 struct {
	Reader     NativeAgentHistoryReader
	Locator    *nativecore.Locator
	Signatures mldsa44.Verifier
	Timeout    time.Duration
}

// ResolveNativeAgentKey implements NativeAgentAuthorityResolver.
func (r NativeAgentAuthorityResolverV1) ResolveNativeAgentKey(scope AuthorityResolutionScopeV1,
	keyID [mldsa44.KeyIDSize]byte, at time.Time, historicalProof []byte) ([]byte, error) {
	if r.Reader == nil || r.Locator == nil || r.Locator.Network == nil || r.Signatures == nil {
		return nil, errors.New("native authority resolver is not configured")
	}
	proof, err := DecodeNativeAgentHistoricalAuthorityProofV1(historicalProof)
	if err != nil {
		return nil, err
	}
	identity, err := r.Locator.Locate(scope.AuthoritySubject)
	if err != nil {
		return nil, fmt.Errorf("native authority subject has no Registry account: %w", err)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultNativeAuthorityReadTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	observation, err := r.Reader.ReadNativeAgentHistory(ctx, proof, scope.AuthoritySubject)
	if err != nil {
		return nil, fmt.Errorf("native authority finalized read: %w", err)
	}
	if at.Unix() <= 0 {
		return nil, errors.New("native authority validation time is invalid")
	}
	return CheckNativeAgentHistoricalAuthorityV1(proof, observation, NativeAgentAuthorityExpectationV1{
		Network: r.Locator.Network, RegistryCodeHash: identity.CodeHash, AgentAccount: identity.Address,
	}, scope.AuthoritySubject, keyID, uint64(at.Unix()))
}

// Verify implements mldsa44.Verifier through the configured verifier.
func (r NativeAgentAuthorityResolverV1) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if r.Signatures == nil {
		return mldsa44.ErrUnavailable
	}
	return r.Signatures.Verify(ctx, use, payload, publicKey, signature)
}
