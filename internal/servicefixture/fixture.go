// Package servicefixture builds shape-valid Service Actor rail inputs for
// tests. The values are synthetic: they are not conformance vectors and no
// hash or BOC here was produced by the contract.
package servicefixture

import (
	"bytes"
	"encoding/json"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
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
