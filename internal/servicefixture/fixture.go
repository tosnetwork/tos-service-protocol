// Package servicefixture builds shape-valid Service Actor rail inputs for
// tests. The values are synthetic: they are not conformance vectors and no
// hash or BOC here was produced by the contract.
package servicefixture

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Network returns a synthetic network domain.
func Network() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

// Settlement names the actor, code hash and attestor a fixture manifest binds.
type Settlement struct {
	ActorAccount  []byte
	ActorCodeHash []byte
	AttestorKey   string
}

// DefaultSettlement is a synthetic key 21 binding.
func DefaultSettlement() Settlement {
	return Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: bytes.Repeat([]byte{0x88}, 32),
		AttestorKey: "mldsa44:" + strings.Repeat("99", 32)}
}

// Manifest returns a valid software-work manifest bound to settlement.
func Manifest(version string, settlement Settlement) nativecore.SoftwareWorkManifestV1 {
	return nativecore.SoftwareWorkManifestV1{
		Protocol: nativecore.SoftwareWorkManifestProtocolV1, Version: version, Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation: nativecore.SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: []string{"test", "./..."},
			WorkingDirectory: "/workspace/source"},
		NetworkPolicy: "none", Limits: nativecore.SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1 << 30,
			ScratchBytes: 2 << 30, OutputBytes: 16 << 20, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.tos.service.software-artifact.v1+tar"},
		ReportMediaTypes:   []string{"application/vnd.tos.service.test-report.v1+json"},
		SuccessCondition:   "exit-code-zero-and-valid-reports", RefundConditions: []string{nativecore.NoAttestedResponseRefund},
		EndpointCommitment:           "sha256:" + strings.Repeat("44", 32),
		ExecutionSignerAuthorization: nativecore.SettlementAttestorAuthorization(settlement.AttestorKey), RetentionSeconds: 86400,
		SupportedAssets: []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.NativeTOSAsset}},
		Settlement: nativecore.SoftwareWorkSettlementV1{Rail: nativecore.ServiceActorRail, ActorWorkchain: 0,
			ActorAccountID: append([]byte(nil), settlement.ActorAccount...), ActorCodeHash: append([]byte(nil), settlement.ActorCodeHash...),
			AttestorKey: settlement.AttestorKey},
	}
}

// ManifestDocumentJSON returns {"manifest": <JSON projection>} of the default
// fixture manifest, the shape tests decode a manifest document from.
func ManifestDocumentJSON() ([]byte, error) {
	manifest, err := json.Marshal(Manifest("1.0.0", DefaultSettlement()))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]json.RawMessage{"manifest": manifest})
}

// Terms returns synthetic open-access terms with the software-work proof
// scheme and the given attestor key id.
func Terms(attestorKeyID [32]byte, metadata [32]byte) nativecore.ServiceActorTermsV1 {
	return nativecore.ServiceActorTermsV1{PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000),
		CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600, RefundClaimWindow: 3600, MetadataHash: metadata,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme, HasAttestor: true, AttestorKeyID: attestorKeyID}
}

// CallTransaction returns a classified successful call carrying the request
// snapshot the contract would emit for it.
func CallTransaction(caller string, requestID uint64, requestHash [32]byte, query uint64, now uint32, lt uint64,
	terms nativecore.ServiceActorTermsV1) (toschain.ActorTransaction, error) {
	termsCell, err := nativecore.BuildServiceActorTermsCell(terms)
	if err != nil {
		return toschain.ActorTransaction{}, err
	}
	callerAddress, err := address.ParseRawAddr(caller)
	if err != nil {
		return toschain.ActorTransaction{}, err
	}
	responseDeadline := uint64(now) + uint64(terms.ResponseSLA)
	snapshot := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).MustStoreUInt(requestID, 64).
		MustStoreAddr(callerAddress).MustStoreSlice(requestHash[:], 256).MustStoreUInt(responseDeadline, 64).
		MustStoreUInt(responseDeadline+uint64(terms.RefundClaimWindow), 64).MustStoreRef(termsCell).EndCell()
	var hash [32]byte
	binary.BigEndian.PutUint64(hash[24:], lt)
	return toschain.ActorTransaction{LT: lt, Hash: hex.EncodeToString(hash[:]), Now: now, Kind: toschain.ActorTxCall, Sender: caller,
		Opcode: nativecore.ServiceActorCallOpcode, QueryID: query,
		Call: &toschain.ActorCallBody{QueryID: query, RequestHash: hex.EncodeToString(requestHash[:]),
			ExpectedTermsHash: hex.EncodeToString(termsCell.Hash())},
		Snapshot: &toschain.ActorSAR1{BodyBOC: base64.StdEncoding.EncodeToString(snapshot.ToBOC())}}, nil
}

// Transition returns a classified successful lifecycle transaction.
func Transition(kind string, requestID uint64, now uint32, lt uint64, sender string) toschain.ActorTransaction {
	var hash [32]byte
	binary.BigEndian.PutUint64(hash[24:], lt)
	return toschain.ActorTransaction{LT: lt, Hash: hex.EncodeToString(hash[:]), Now: now, Kind: kind, RequestID: requestID,
		Sender: sender, Signed: kind == toschain.ActorTxRespond}
}

// ActorData returns consistent actor data holding the given live requests.
func ActorData(owner string, policy nativecore.ServiceActorPolicyV1, next uint64,
	pending map[uint64]nativecore.ServiceActorRequestSnapshotV1, refunds map[uint64]nativecore.ServiceActorRequestSnapshotV1) (*nativecore.ServiceActorDataV1, error) {
	ownerAddress, err := nativecore.StandardAddress(owner)
	if err != nil {
		return nil, err
	}
	data := &nativecore.ServiceActorDataV1{Owner: ownerAddress, Active: true, NextRequestID: next, Policy: policy,
		Accounting: nativecore.ServiceActorAccountingV1{WithdrawableRevenue: new(big.Int), LockedStorageFees: new(big.Int),
			PendingLiability: new(big.Int), RefundableLiability: new(big.Int)},
		Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{}, Refunds: map[uint64]nativecore.ServiceActorRefundV1{},
		CallerLiveCounts: map[[32]byte]uint32{}}
	for id, s := range pending {
		data.Pending[id] = nativecore.ServiceActorPendingRequestV1{Caller: s.Caller, Price: s.Terms.PricePerCall,
			StorageFee: s.Terms.StorageFee, CleanupBounty: s.Terms.CleanupBounty, ResponseDeadline: s.ResponseDeadline,
			RefundClaimDeadline: s.RefundClaimDeadline, PolicyVersion: s.Terms.PolicyVersion, RequestHash: s.RequestHash,
			TermsHash: s.TermsHash, HasAttestor: s.Terms.HasAttestor, AttestorKeyID: s.Terms.AttestorKeyID}
		data.Accounting.PendingLiability.Add(data.Accounting.PendingLiability, s.Terms.PricePerCall)
		data.Accounting.LockedStorageFees.Add(data.Accounting.LockedStorageFees, s.Terms.StorageFee)
		key, err := s.Caller.SliceHash()
		if err != nil {
			return nil, err
		}
		data.CallerLiveCounts[key]++
	}
	for id, s := range refunds {
		data.Refunds[id] = nativecore.ServiceActorRefundV1{Caller: s.Caller, Price: s.Terms.PricePerCall, StorageFee: s.Terms.StorageFee,
			CleanupBounty: s.Terms.CleanupBounty, RefundClaimDeadline: s.RefundClaimDeadline}
		data.Accounting.RefundableLiability.Add(data.Accounting.RefundableLiability, s.Terms.PricePerCall)
		data.Accounting.LockedStorageFees.Add(data.Accounting.LockedStorageFees, s.Terms.StorageFee)
		key, err := s.Caller.SliceHash()
		if err != nil {
			return nil, err
		}
		data.CallerLiveCounts[key]++
	}
	data.PendingCount, data.LiveCount = uint32(len(pending)), uint32(len(pending)+len(refunds))
	return data, nil
}
