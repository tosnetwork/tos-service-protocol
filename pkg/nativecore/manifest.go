package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const SoftwareWorkManifestProtocolV1 = "tos.service.software-work-manifest.v1"

var (
	manifestVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	mediaTypePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$`)
)

// SoftwareWorkManifestV1 is an off-chain, content-addressed execution
// contract. It deliberately does not contain capability_id: the Capability ID
// commits to this manifest's digest, so including the ID here would create a
// circular identity definition.
type SoftwareWorkManifestV1 struct {
	Protocol                     string                   `json:"protocol" cbor:"1,keyasint"`
	Version                      string                   `json:"version" cbor:"2,keyasint"`
	Name                         string                   `json:"name" cbor:"3,keyasint"`
	Description                  string                   `json:"description" cbor:"4,keyasint"`
	Operation                    string                   `json:"operation" cbor:"5,keyasint"`
	AcceptedSourceKinds          []string                 `json:"accepted_source_kinds" cbor:"6,keyasint"`
	InputSchemaDigest            string                   `json:"input_schema_digest" cbor:"7,keyasint"`
	OutputSchemaDigest           string                   `json:"output_schema_digest" cbor:"8,keyasint"`
	ToolchainDigest              string                   `json:"toolchain_digest" cbor:"9,keyasint"`
	Invocation                   SoftwareWorkInvocationV1 `json:"invocation" cbor:"10,keyasint"`
	NetworkPolicy                string                   `json:"network_policy" cbor:"11,keyasint"`
	Limits                       SoftwareWorkLimitsV1     `json:"limits" cbor:"12,keyasint"`
	ArtifactMediaTypes           []string                 `json:"artifact_media_types" cbor:"13,keyasint"`
	ReportMediaTypes             []string                 `json:"report_media_types" cbor:"14,keyasint"`
	SuccessCondition             string                   `json:"success_condition" cbor:"15,keyasint"`
	RefundConditions             []string                 `json:"refund_conditions" cbor:"16,keyasint"`
	EndpointCommitment           string                   `json:"endpoint_commitment" cbor:"17,keyasint"`
	ExecutionSignerAuthorization string                   `json:"execution_signer_authorization" cbor:"18,keyasint"`
	RetentionSeconds             uint64                   `json:"retention_seconds" cbor:"19,keyasint"`
	SupportedAssets              []SoftwareWorkAssetV1    `json:"supported_assets" cbor:"20,keyasint"`
	Settlement                   SoftwareWorkSettlementV1 `json:"settlement" cbor:"21,keyasint"`
}

type SoftwareWorkInvocationV1 struct {
	Executable       string   `json:"executable" cbor:"1,keyasint"`
	Arguments        []string `json:"arguments" cbor:"2,keyasint"`
	WorkingDirectory string   `json:"working_directory" cbor:"3,keyasint"`
}

type SoftwareWorkLimitsV1 struct {
	CPUMillis       uint64 `json:"cpu_millis" cbor:"1,keyasint"`
	MemoryBytes     uint64 `json:"memory_bytes" cbor:"2,keyasint"`
	ScratchBytes    uint64 `json:"scratch_bytes" cbor:"3,keyasint"`
	OutputBytes     uint64 `json:"output_bytes" cbor:"4,keyasint"`
	WallClockMillis uint64 `json:"wall_clock_millis" cbor:"5,keyasint"`
}

// SoftwareWorkAssetV1 is one key 20 entry; the only admitted value is the
// native TOS entry {0: "native-tos"}.
type SoftwareWorkAssetV1 struct {
	Kind string `json:"kind" cbor:"0,keyasint"`
}

// SoftwareWorkSettlementV1 is manifest key 21: the Service Actor that settles
// this Capability version, published under the owner Agent's policy.
type SoftwareWorkSettlementV1 struct {
	Rail           string `json:"rail" cbor:"1,keyasint"`
	ActorWorkchain int32  `json:"actor_workchain" cbor:"2,keyasint"`
	ActorAccountID []byte `json:"actor_account_id" cbor:"3,keyasint"`
	ActorCodeHash  []byte `json:"actor_code_hash" cbor:"4,keyasint"`
	AttestorKey    string `json:"attestor_key" cbor:"5,keyasint"`
}

// NativeTOSAsset is the key 20 identity of native TOS.
const NativeTOSAsset = "native-tos"

// NoAttestedResponseRefund is the only key 16 value of this profile.
const NoAttestedResponseRefund = "no-attested-response-before-deadline"

// SettlementAttestorAuthorization is the key 18 value a key 21 attestor text
// commits to: SHA-256 over its exact ASCII bytes.
func SettlementAttestorAuthorization(attestorKeyText string) string {
	digest := sha256.Sum256([]byte(attestorKeyText))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateSettlement(manifest SoftwareWorkManifestV1) error {
	settlement := manifest.Settlement
	if settlement.Rail != ServiceActorRail || settlement.ActorWorkchain != 0 {
		return errors.New("manifest settlement must name a workchain 0 Service Actor")
	}
	for name, value := range map[string][]byte{"actor account": settlement.ActorAccountID, "actor code hash": settlement.ActorCodeHash} {
		if len(value) != 32 || equalBytes(value, make([]byte, 32)) {
			return fmt.Errorf("manifest settlement %s must be 32 non-zero bytes", name)
		}
	}
	if _, err := mldsa44.ParseKeyIDText(settlement.AttestorKey); err != nil {
		return errors.New("manifest settlement attestor key is not mldsa44:<key id>")
	}
	if manifest.ExecutionSignerAuthorization != SettlementAttestorAuthorization(settlement.AttestorKey) {
		return errors.New("manifest key 18 does not commit to the key 21 attestor")
	}
	return nil
}

func DecodeSoftwareWorkManifestJSON(data []byte) (SoftwareWorkManifestV1, error) {
	var manifest SoftwareWorkManifestV1
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SoftwareWorkManifestV1{}, errors.New("multiple manifest JSON values or trailing data")
	}
	if err := ValidateSoftwareWorkManifest(manifest); err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	return manifest, nil
}

// DecodeCanonicalSoftwareWorkManifestCBOR accepts only the exact deterministic
// representation produced by CanonicalSoftwareWorkManifest. This prevents a
// content store from serving alternate encodings for one semantic manifest.
func DecodeCanonicalSoftwareWorkManifestCBOR(data []byte) (SoftwareWorkManifestV1, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return SoftwareWorkManifestV1{}, errors.New("software-work manifest CBOR is empty or oversized")
	}
	var manifest SoftwareWorkManifestV1
	if err := cbor.Unmarshal(data, &manifest); err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	canonical, _, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	if !bytes.Equal(data, canonical) {
		return SoftwareWorkManifestV1{}, errors.New("software-work manifest CBOR is not canonical")
	}
	return manifest, nil
}

func CanonicalSoftwareWorkManifest(manifest SoftwareWorkManifestV1) ([]byte, string, error) {
	if err := ValidateSoftwareWorkManifest(manifest); err != nil {
		return nil, "", err
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, "", err
	}
	encoded, err := mode.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return encoded, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateSoftwareWorkManifest(manifest SoftwareWorkManifestV1) error {
	if manifest.Protocol != SoftwareWorkManifestProtocolV1 || !manifestVersionPattern.MatchString(manifest.Version) {
		return errors.New("invalid software-work manifest protocol or version")
	}
	if !boundedPrintable(manifest.Name, 1, 128) || !boundedPrintable(manifest.Description, 1, 2048) {
		return errors.New("invalid software-work manifest name or description")
	}
	operations := map[string]bool{"compile": true, "test": true, "static-analysis": true, "dependency-scan": true,
		"vulnerability-scan": true, "reproducible-build": true, "bounded-transform-and-test": true}
	if !operations[manifest.Operation] {
		return errors.New("unsupported software-work operation")
	}
	if err := validateSortedEnum(manifest.AcceptedSourceKinds, 1, 8, map[string]bool{"content-addressed-archive": true, "immutable-repository-commit": true}); err != nil {
		return fmt.Errorf("invalid accepted source kinds: %w", err)
	}
	for name, value := range map[string]string{"input schema": manifest.InputSchemaDigest, "output schema": manifest.OutputSchemaDigest,
		"toolchain": manifest.ToolchainDigest, "endpoint": manifest.EndpointCommitment, "execution signer": manifest.ExecutionSignerAuthorization} {
		if !canonicalDigest(value, "sha256:") {
			return fmt.Errorf("invalid %s digest", name)
		}
	}
	if err := validateInvocation(manifest.Invocation); err != nil {
		return err
	}
	if manifest.NetworkPolicy != "none" {
		return errors.New("software-work v1 requires network_policy none")
	}
	limits := manifest.Limits
	if limits.CPUMillis == 0 || limits.CPUMillis > 86_400_000 || limits.MemoryBytes < 16<<20 || limits.MemoryBytes > 64<<30 ||
		limits.ScratchBytes == 0 || limits.ScratchBytes > 1<<40 || limits.OutputBytes == 0 || limits.OutputBytes > 1<<30 ||
		limits.WallClockMillis == 0 || limits.WallClockMillis > 86_400_000 {
		return errors.New("software-work resource limits are absent or out of bounds")
	}
	if err := validateMediaTypes(manifest.ArtifactMediaTypes); err != nil {
		return fmt.Errorf("invalid artifact media types: %w", err)
	}
	if err := validateMediaTypes(manifest.ReportMediaTypes); err != nil {
		return fmt.Errorf("invalid report media types: %w", err)
	}
	if manifest.SuccessCondition != "exit-code-zero-and-valid-reports" {
		return errors.New("unsupported software-work success condition")
	}
	if len(manifest.RefundConditions) != 1 || manifest.RefundConditions[0] != NoAttestedResponseRefund {
		return errors.New("software-work v1 supports only the no-attested-response-before-deadline refund")
	}
	if manifest.RetentionSeconds < 3600 || manifest.RetentionSeconds > 30*24*3600 {
		return errors.New("retention_seconds is out of bounds")
	}
	if len(manifest.SupportedAssets) != 1 || manifest.SupportedAssets[0].Kind != NativeTOSAsset {
		return errors.New("supported_assets must be exactly the native TOS entry")
	}
	return validateSettlement(manifest)
}

func validateInvocation(invocation SoftwareWorkInvocationV1) error {
	if !strings.HasPrefix(invocation.Executable, "/") || !boundedPrintable(invocation.Executable, 2, 256) ||
		!strings.HasPrefix(invocation.WorkingDirectory, "/workspace") || !boundedPrintable(invocation.WorkingDirectory, 10, 256) {
		return errors.New("invocation paths must be bounded absolute sandbox paths")
	}
	base := invocation.Executable[strings.LastIndex(invocation.Executable, "/")+1:]
	forbidden := map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "cmd.exe": true, "powershell": true}
	if forbidden[strings.ToLower(base)] || len(invocation.Arguments) > 64 {
		return errors.New("shell interpreters and unbounded argument lists are forbidden")
	}
	for _, argument := range invocation.Arguments {
		if !boundedPrintable(argument, 0, 512) {
			return errors.New("invalid invocation argument")
		}
	}
	return nil
}

func validateMediaTypes(values []string) error {
	if len(values) == 0 || len(values) > 16 || !sort.StringsAreSorted(values) {
		return errors.New("list is absent, oversized, or unsorted")
	}
	for index, value := range values {
		if !mediaTypePattern.MatchString(value) || index > 0 && value == values[index-1] {
			return errors.New("invalid or duplicate media type")
		}
	}
	return nil
}

func validateSortedEnum(values []string, minimum, maximum int, allowed map[string]bool) error {
	if len(values) < minimum || len(values) > maximum || !sort.StringsAreSorted(values) {
		return errors.New("list is absent, oversized, or unsorted")
	}
	for index, value := range values {
		if !allowed[value] || index > 0 && value == values[index-1] {
			return errors.New("invalid or duplicate value")
		}
	}
	return nil
}

func boundedPrintable(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func lowerHex32(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, item := range decoded {
		if item != 0 {
			return true
		}
	}
	return false
}

func canonicalDigest(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && lowerHex32(strings.TrimPrefix(value, prefix))
}
