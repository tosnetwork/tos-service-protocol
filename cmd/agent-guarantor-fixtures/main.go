// Command agent-guarantor-fixtures emits the released Guarantor V1 dispatch
// registries and canonical digests for independent implementations.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

func main() {
	output := flag.String("output", "", "write fixtures to this path instead of stdout")
	signatureVector := flag.String("signature-vector", "",
		"the shared Agent Guarantor ML-DSA-44 signature vector (pkg/agentguarantor/testdata/agent-guarantor-signature-vector.json)")
	flag.Parse()
	if *signatureVector == "" {
		fatal(fmt.Errorf("-signature-vector is required"))
	}
	nativeVectors, err := nativeAuthorizationVectors(*signatureVector)
	if err != nil {
		fatal(err)
	}
	objects := guarantor.ReleasedObjectVerifierRegistryV1()
	mutations := guarantor.ReleasedMutationVerifierRegistryV1()
	objectCanonical, err := codec.Marshal(objects)
	if err != nil {
		fatal(err)
	}
	mutationCanonical, err := codec.Marshal(mutations)
	if err != nil {
		fatal(err)
	}
	objectDigest, err := guarantor.ObjectVerifierRegistryDigestV1()
	if err != nil {
		fatal(err)
	}
	mutationDigest, err := guarantor.MutationVerifierRegistryDigestV1()
	if err != nil {
		fatal(err)
	}
	genesis, err := guarantor.NewAcceptedCoverageRecord(fixtureDigest("1"), "obligation:coverage", fixtureDigest("2"), fixtureDigest("3"))
	if err != nil {
		fatal(err)
	}
	activated, err := guarantor.ActivateAcceptedCoverage(genesis, 1, 1, fixtureDigest("4"))
	if err != nil {
		fatal(err)
	}
	frozen, err := guarantor.FreezeClaimFiling(activated, 2, 2, 0, fixtureDigest("5"), fixtureDigest("6"), false)
	if err != nil {
		fatal(err)
	}
	stateVectors := []struct {
		Name             string                   `json:"name"`
		State            guarantor.CoverageRecord `json:"state"`
		CanonicalCBORHex string                   `json:"canonical_cbor_hex"`
		Digest           string                   `json:"digest"`
	}{
		{Name: "accepted-genesis", State: genesis}, {Name: "activated", State: activated}, {Name: "filing-frozen-zero-claims", State: frozen}}
	for index := range stateVectors {
		canonical, encodeErr := codec.Marshal(stateVectors[index].State)
		if encodeErr != nil {
			fatal(encodeErr)
		}
		stateVectors[index].CanonicalCBORHex = hex.EncodeToString(canonical)
		stateVectors[index].Digest, err = guarantor.Digest("tos.service.agent-guarantor-coverage-state-vector.v1", stateVectors[index].State)
		if err != nil {
			fatal(err)
		}
	}
	actionKind := "payment.domain-bound"
	actionValues := map[string]commerce.SemanticValue{
		"owner_id":               commerce.ID("owner:guarantor"),
		"agent_id":               commerce.ID("agent:guarantor"),
		"agreement_body_digest":  commerce.Digest32(fixtureDigest("1")),
		"obligation_instance_id": commerce.Digest32(fixtureDigest("2")),
		"payer_id":               commerce.ID("agent:guarantor"),
		"payee_id":               commerce.ID("agent:beneficiary"),
		"network_domain_digest":  commerce.Digest32(fixtureDigest("3")),
		"asset_digest":           commerce.Digest32(fixtureDigest("4")),
		"amount_atomic":          commerce.ID("1250000"),
		"destination_digest":     commerce.Digest32(fixtureDigest("5")),
	}
	stableActionID, semanticPreimage, err := commerce.DeriveStableActionID(actionKind, actionValues)
	if err != nil {
		fatal(err)
	}
	semanticFields, err := commerce.ExportSemanticFields(actionKind, actionValues)
	if err != nil {
		fatal(err)
	}
	actionVectors := []struct {
		Name           string                        `json:"name"`
		ActionKind     string                        `json:"action_kind"`
		Fields         []commerce.SemanticFieldValue `json:"fields"`
		StableActionID string                        `json:"stable_action_id"`
		PreimageHex    string                        `json:"preimage_hex"`
	}{
		{Name: "guarantor-domain-bound-payout", ActionKind: actionKind, Fields: semanticFields,
			StableActionID: stableActionID, PreimageHex: hex.EncodeToString(semanticPreimage)},
	}
	sizeVectors, err := guarantor.ReleasedSizeVectorsV1()
	if err != nil {
		fatal(err)
	}
	sizeLimits := struct {
		CanonicalBytes        int                      `json:"canonical_bytes"`
		StringBytes           int                      `json:"string_bytes"`
		JSONBytes             int                      `json:"json_bytes"`
		DefaultCanonicalBytes int                      `json:"default_canonical_bytes"`
		DefaultStringBytes    int                      `json:"default_string_bytes"`
		Domain                string                   `json:"domain"`
		Vectors               []guarantor.SizeVectorV1 `json:"vectors"`
	}{guarantor.GuarantorCodecLimitsV1.CanonicalBytes, guarantor.GuarantorCodecLimitsV1.StringBytes,
		guarantor.GuarantorCodecLimitsV1.JSONBytes, codec.MaxCanonicalBytes, codec.MaxStringBytes,
		guarantor.SizeVectorDomainV1, sizeVectors}
	document := struct {
		Schema                        string                               `json:"schema"`
		ProfileURI                    string                               `json:"profile_uri"`
		CommerceProfileContentType    string                               `json:"commerce_profile_event_content_type"`
		CommerceCarriageRegistry      []guarantor.CommerceCarriageObjectV1 `json:"commerce_carriage_registry"`
		ObjectRegistry                guarantor.ObjectVerifierRegistryV1   `json:"object_registry"`
		ObjectRegistryCanonicalCBOR   string                               `json:"object_registry_canonical_cbor_hex"`
		ObjectRegistryDigest          string                               `json:"object_registry_digest"`
		MutationRegistry              guarantor.MutationVerifierRegistryV1 `json:"mutation_registry"`
		MutationRegistryCanonicalCBOR string                               `json:"mutation_registry_canonical_cbor_hex"`
		MutationRegistryDigest        string                               `json:"mutation_registry_digest"`
		CoverageStateVectors          interface{}                          `json:"coverage_state_vectors"`
		SemanticActionVectors         interface{}                          `json:"semantic_action_vectors"`
		NativeAuthorizationVectors    interface{}                          `json:"native_authorization_vectors"`
		GuarantorSizeLimits           interface{}                          `json:"guarantor_size_limits"`
	}{"tos.service.agent-guarantor-conformance-fixture.v1", guarantor.ProfileURI,
		commerce.CommerceProfileEventContentType, guarantor.ReleasedCommerceCarriageObjectsV1(), objects,
		hex.EncodeToString(objectCanonical), objectDigest, mutations, hex.EncodeToString(mutationCanonical), mutationDigest,
		stateVectors, actionVectors, nativeVectors, sizeLimits}
	var writer io.Writer = os.Stdout
	var file *os.File
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		fatal(err)
	}
}

type nativeRefusalVector struct {
	Name            string `json:"name"`
	SignatureDomain string `json:"signature_domain"`
	Signature       string `json:"signature"`
}

type nativeAuthorizationVector struct {
	Name                       string                                          `json:"name"`
	Statement                  guarantor.AuthorizationStatementV1              `json:"statement"`
	StatementCanonicalCBOR     string                                          `json:"statement_canonical_cbor_hex"`
	SignatureDomain            string                                          `json:"signature_domain"`
	Context                    string                                          `json:"context"`
	MessageHex                 string                                          `json:"message_hex"`
	PublicKeyHex               string                                          `json:"public_key_hex"`
	HistoricalProof            guarantor.NativeAgentHistoricalAuthorityProofV1 `json:"historical_authority_proof"`
	HistoricalProofCBOR        string                                          `json:"historical_authority_proof_canonical_cbor_hex"`
	Authorization              guarantor.ProfileQualifiedObjectAuthorizationV1 `json:"authorization"`
	AuthorizationCanonicalCBOR string                                          `json:"authorization_canonical_cbor_hex"`
	Refusals                   []nativeRefusalVector                           `json:"refusals"`
}

// nativeAuthorizationVectors builds the native ML-DSA-44 authorization vector
// from the shared signature vector. The statement, message, text forms and
// canonical encodings are produced here by the implementation; the
// signatures are the vector's deterministic bytes, and the message this
// implementation computes must equal the one they sign.
func nativeAuthorizationVectors(path string) ([]nativeAuthorizationVector, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var source struct {
		Schema           string `json:"schema"`
		SeedHex          string `json:"seed_hex"`
		Context          string `json:"context"`
		StatementCBORHex string `json:"statement_cbor_hex"`
		SignatureDomain  string `json:"signature_domain"`
		MessageHex       string `json:"message_hex"`
		PublicKeyHex     string `json:"public_key_hex"`
		KeyIDHex         string `json:"key_id_hex"`
		SignatureHex     string `json:"signature_hex"`
		Refusals         []struct {
			Name            string `json:"name"`
			Mode            string `json:"mode"`
			Context         string `json:"context"`
			SignatureDomain string `json:"signature_domain"`
			MessageHex      string `json:"message_hex"`
			SignatureHex    string `json:"signature_hex"`
		} `json:"refusals"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("signature vector: %w", err)
	}
	if source.Schema != "tos.agent-guarantor-signature-vector.v1" || source.Context != "TOS-AGENT-GUARANTOR-V1" {
		return nil, fmt.Errorf("signature vector has an unexpected schema or context")
	}
	statement := guarantor.AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: "agent_" + strings.Repeat("5a", 32),
		ProfileURI: guarantor.ProfileURI, ProfileVersion: 1, ProfileDigest: fixtureDigest("1"),
		AuthorizedObjectKind: "quote-request", AuthorizedBodyDigest: fixtureDigest("2"), ValidationTimeUnix: 1767225600}
	statementCBOR, err := codec.Marshal(statement)
	if err != nil {
		return nil, err
	}
	message, err := guarantor.NativeAuthorizationMessage(source.SignatureDomain, statement)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(statementCBOR) != source.StatementCBORHex || hex.EncodeToString(message) != source.MessageHex {
		return nil, fmt.Errorf("the implementation's statement or message differs from the signature vector")
	}
	publicKey, err := hex.DecodeString(source.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	keyID, err := mldsa44.KeyID(publicKey)
	if err != nil || hex.EncodeToString(keyID[:]) != source.KeyIDHex {
		return nil, fmt.Errorf("signature vector key ID does not derive from its key")
	}
	signatureText := func(value string) (string, error) {
		signature, err := hex.DecodeString(value)
		if err != nil {
			return "", err
		}
		return guarantor.NativeAuthorizationSignatureText(signature)
	}
	signature, err := signatureText(source.SignatureHex)
	if err != nil {
		return nil, err
	}
	proof := guarantor.NativeAgentHistoricalAuthorityProofV1{SchemaVersion: 1, NetworkID: "tos:global-id:2",
		GenesisRootHash: fixtureDigest("a"), GenesisFileHash: fixtureDigest("b"),
		RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("d", 64), AgentAccount: "0:" + strings.Repeat("c", 64),
		EffectiveTransaction: guarantor.FinalizedTransactionRefV1{LogicalTime: 100, TransactionHash: fixtureDigest("3")},
		EffectiveCheckpoint:  guarantor.FinalizedCheckpointRefV1{Sequence: 10, RootHash: fixtureDigest("4"), FileHash: fixtureDigest("5")},
		BoundCheckpoint:      guarantor.FinalizedCheckpointRefV1{Sequence: 20, RootHash: fixtureDigest("6"), FileHash: fixtureDigest("7")}}
	proofCBOR, err := guarantor.EncodeNativeAgentHistoricalAuthorityProofV1(proof)
	if err != nil {
		return nil, err
	}
	authorization := guarantor.ProfileQualifiedObjectAuthorizationV1{AuthoritySubject: statement.AuthoritySubject,
		ProfileURI: statement.ProfileURI, ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedObjectKind: statement.AuthorizedObjectKind, AuthorizedBodyDigest: statement.AuthorizedBodyDigest,
		ValidationTimeUnix: statement.ValidationTimeUnix, EvidenceContentType: guarantor.NativeAuthorizationContentType,
		Evidence: guarantor.NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: mldsa44.KeyIDText(keyID), Signature: signature,
			HistoricalAuthorityProof: proofCBOR}}
	authorizationCBOR, err := codec.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	refusals := make([]nativeRefusalVector, 0, len(source.Refusals))
	for _, refusal := range source.Refusals {
		text, err := signatureText(refusal.SignatureHex)
		if err != nil {
			return nil, err
		}
		refusals = append(refusals, nativeRefusalVector{Name: refusal.Name, SignatureDomain: refusal.SignatureDomain, Signature: text})
	}
	return []nativeAuthorizationVector{{Name: "quote-request-native-mldsa44", Statement: statement,
		StatementCanonicalCBOR: hex.EncodeToString(statementCBOR), SignatureDomain: source.SignatureDomain,
		Context: source.Context, MessageHex: hex.EncodeToString(message), PublicKeyHex: source.PublicKeyHex,
		HistoricalProof: proof, HistoricalProofCBOR: hex.EncodeToString(proofCBOR), Authorization: authorization,
		AuthorizationCanonicalCBOR: hex.EncodeToString(authorizationCBOR), Refusals: refusals}}, nil
}

func fixtureDigest(ch string) string {
	value := "sha256:"
	for range 64 {
		value += ch
	}
	return value
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
