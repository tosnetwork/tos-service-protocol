package agentguarantor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// signatureVector is the shared Agent Guarantor ML-DSA-44 vector, a byte copy
// of the file the tosctl implementation reproduces from its seed.
type signatureVector struct {
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

// vectorStatement is the statement the vector signs, written out here so the
// Go encoder, not the vector, produces its bytes.
var vectorStatement = AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: "agent_" + strings.Repeat("5a", 32),
	ProfileURI: "tos.agent-service.guarantor.v1", ProfileVersion: 1, ProfileDigest: "sha256:" + strings.Repeat("11", 32),
	AuthorizedObjectKind: "quote-request", AuthorizedBodyDigest: "sha256:" + strings.Repeat("22", 32),
	ValidationTimeUnix: 1767225600}

func loadSignatureVector(t testing.TB) signatureVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/agent-guarantor-signature-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector signatureVector
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "tos.agent-guarantor-signature-vector.v1" || vector.Context != "TOS-AGENT-GUARANTOR-V1" ||
		len(vector.Refusals) != 7 {
		t.Fatalf("unexpected signature vector shape: %s, %s, %d refusals", vector.Schema, vector.Context, len(vector.Refusals))
	}
	return vector
}

func mustHex(t testing.TB, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// fixedKeyResolver resolves every key ID to one key, as a historical proof
// would, and verifies through the given verifier.
type fixedKeyResolver struct {
	key      []byte
	verifier mldsa44.Verifier
}

func (fixedKeyResolver) ResolveGuarantorAuthority(AuthorityResolutionScopeV1, string, time.Time, []byte) error {
	return errors.New("no Action Authority keys in this test")
}

func (r fixedKeyResolver) ResolveNativeAgentKey(_ AuthorityResolutionScopeV1, _ [mldsa44.KeyIDSize]byte, _ time.Time,
	proof []byte) ([]byte, error) {
	if len(proof) == 0 {
		return nil, errTestAuthority
	}
	return append([]byte(nil), r.key...), nil
}

func (r fixedKeyResolver) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	return r.verifier.Verify(ctx, use, payload, publicKey, signature)
}

func vectorAuthorization(t testing.TB, vector signatureVector, signatureHex string) ProfileQualifiedObjectAuthorizationV1 {
	t.Helper()
	signatureText, err := NativeAuthorizationSignatureText(mustHex(t, signatureHex))
	if err != nil {
		t.Fatal(err)
	}
	statement := vectorStatement
	return ProfileQualifiedObjectAuthorizationV1{AuthoritySubject: statement.AuthoritySubject, ProfileURI: statement.ProfileURI,
		ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedObjectKind: statement.AuthorizedObjectKind, AuthorizedBodyDigest: statement.AuthorizedBodyDigest,
		ValidationTimeUnix: statement.ValidationTimeUnix, EvidenceContentType: NativeAuthorizationContentType,
		Evidence: NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: "mldsa44:" + vector.KeyIDHex, Signature: signatureText,
			HistoricalAuthorityProof: []byte("located-by-the-resolver")}}
}

// The Go encoder reproduces the vector's statement bytes and message, and the
// pinned helper accepts its Pure signature under TOS-AGENT-GUARANTOR-V1 and
// refuses every refusal signature: pre-hash, empty, registry, packet,
// contact and Service Actor contexts, and another object kind's domain.
func TestNativeVectorVerifiesThroughTheHelperAndRefusesEveryOtherUse(t *testing.T) {
	helper := mldsa44test.RequireTosctl(t)
	vector := loadSignatureVector(t)
	canonical, err := codec.Marshal(vectorStatement)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(canonical) != vector.StatementCBORHex {
		t.Fatalf("Go statement CBOR differs from the vector:\n%x\n%s", canonical, vector.StatementCBORHex)
	}
	if vector.SignatureDomain != "tos.service.agent-guarantor-quote-request-signature.v1" {
		t.Fatalf("vector domain = %s", vector.SignatureDomain)
	}
	message, err := NativeAuthorizationMessage(vector.SignatureDomain, vectorStatement)
	if err != nil || hex.EncodeToString(message) != vector.MessageHex {
		t.Fatalf("Go message %x differs from the vector %s: %v", message, vector.MessageHex, err)
	}
	publicKey := mustHex(t, vector.PublicKeyHex)
	keyID, err := mldsa44.KeyID(publicKey)
	if err != nil || hex.EncodeToString(keyID[:]) != vector.KeyIDHex {
		t.Fatalf("key ID %x differs from the vector: %v", keyID, err)
	}
	resolver := fixedKeyResolver{key: publicKey, verifier: helper}
	now := time.Unix(int64(vectorStatement.ValidationTimeUnix), 0)
	verify := func(authorization ProfileQualifiedObjectAuthorizationV1, domain string) error {
		return VerifyObjectAuthorization(authorization, vectorStatement.AuthorizedObjectKind,
			vectorStatement.AuthorizedBodyDigest, domain, resolver, now)
	}
	if err := verify(vectorAuthorization(t, vector, vector.SignatureHex), vector.SignatureDomain); err != nil {
		t.Fatalf("the vector's Pure signature was refused: %v", err)
	}
	if err := verify(vectorAuthorization(t, vector, vector.SignatureHex),
		"tos.service.agent-guarantor-firm-offer-signature.v1"); err == nil {
		t.Fatal("a quote-request signature verified under the firm-offer domain")
	}
	want := map[string]bool{"hash-ml-dsa-sha256": true, "empty-context": true, "registry-context": true,
		"agent-packet-context": true, "agent-contact-context": true, "service-actor-context": true, "firm-offer-domain": true}
	for _, refusal := range vector.Refusals {
		if !want[refusal.Name] {
			t.Fatalf("unexpected refusal %q", refusal.Name)
		}
		delete(want, refusal.Name)
		if refusal.Name != "firm-offer-domain" && refusal.MessageHex != vector.MessageHex {
			t.Fatalf("%s does not sign the vector message", refusal.Name)
		}
		if err := verify(vectorAuthorization(t, vector, refusal.SignatureHex), vector.SignatureDomain); err == nil {
			t.Fatalf("%s verified as a Guarantor authorization", refusal.Name)
		}
		if err := helper.Verify(context.Background(), mldsa44.UseAgentGuarantor, message, publicKey,
			mustHex(t, refusal.SignatureHex)); !errors.Is(err, mldsa44.ErrInvalidSignature) {
			t.Fatalf("helper answered %v for %s", err, refusal.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("vector lacks refusals %v", want)
	}
}

// A custody-held controller signs through the helper and the result verifies;
// the same evidence on another body does not.
func TestCustodySignedNativeAuthorizationVerifies(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "alpha")
	helper := mldsa44test.RequireTosctl(t)
	statement := vectorStatement
	authorization, err := SignObjectAuthorization(context.Background(), statement, vectorStatementDomain, custody.Signer,
		"alpha", []byte("located-by-the-resolver"))
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Evidence.KeyID != custody.KeyID(t, "alpha") {
		t.Fatalf("evidence names key %s", authorization.Evidence.KeyID)
	}
	resolver := fixedKeyResolver{key: custody.PublicKeys["alpha"], verifier: helper}
	now := time.Unix(int64(statement.ValidationTimeUnix), 0)
	if err := VerifyObjectAuthorization(authorization, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
		vectorStatementDomain, resolver, now); err != nil {
		t.Fatal(err)
	}
	moved := authorization
	moved.AuthorizedBodyDigest = "sha256:" + strings.Repeat("33", 32)
	if err := VerifyObjectAuthorization(moved, statement.AuthorizedObjectKind, moved.AuthorizedBodyDigest,
		vectorStatementDomain, resolver, now); err == nil {
		t.Fatal("authorization verified over another body")
	}
	// A resolved key that does not derive the evidence's key ID is refused
	// even though the signature is the key's own.
	other := mldsa44test.NewCustody(t, "beta")
	if err := VerifyObjectAuthorization(authorization, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
		vectorStatementDomain, fixedKeyResolver{key: other.PublicKeys["beta"], verifier: helper}, now); err == nil {
		t.Fatal("a key that does not derive the key ID was used")
	}
}

const vectorStatementDomain = "tos.service.agent-guarantor-quote-request-signature.v1"

// The resolved key must derive the evidence's key ID even when the signature
// is valid for that key: a resolver answering with another controller's key
// cannot authorize the named one.
func TestResolvedKeyMustDeriveTheEvidenceKeyID(t *testing.T) {
	statement := vectorStatement
	now := time.Unix(int64(statement.ValidationTimeUnix), 0)
	signed := testSignAuthorization(t, statement, vectorStatementDomain, "beta", []byte("proof"))
	resolver := fixedKeyResolver{key: nativeTestFake.PublicKey("beta"), verifier: nativeTestFake}
	if err := VerifyObjectAuthorization(signed, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
		vectorStatementDomain, resolver, now); err != nil {
		t.Fatalf("control: beta's own evidence was refused: %v", err)
	}
	renamed := signed
	renamed.Evidence.KeyID = nativeTestFake.KeyID("alpha")
	if err := VerifyObjectAuthorization(renamed, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
		vectorStatementDomain, resolver, now); err == nil {
		t.Fatal("a key that does not derive the evidence key ID authorized it")
	}
}

// Only the exact text forms are accepted: mldsa44:<64 lowercase hex> and
// mldsa44:<unpadded URL-safe Base64 of 2,420 bytes>.
func TestNativeTextFormsAreExact(t *testing.T) {
	statement := vectorStatement
	statement.AuthoritySubject = "agent:text-forms"
	authorization := testSignAuthorization(t, statement, vectorStatementDomain, "text-forms", []byte("proof"))
	now := time.Unix(int64(statement.ValidationTimeUnix), 0)
	verify := func(value ProfileQualifiedObjectAuthorizationV1) error {
		return VerifyObjectAuthorization(value, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
			vectorStatementDomain, allowAuthorityResolver{}, now)
	}
	if err := verify(authorization); err != nil {
		t.Fatalf("canonical evidence refused: %v", err)
	}
	keyHex := strings.TrimPrefix(authorization.Evidence.KeyID, "mldsa44:")
	signature, err := ParseNativeAuthorizationSignatureText(authorization.Evidence.Signature)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(authorization.Evidence.Signature, "mldsa44:")
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", encoded[len(encoded)-1])
	trailing := encoded[:len(encoded)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last^1])
	std := base64.StdEncoding.EncodeToString(signature)
	for name, keyID := range map[string]string{
		"uppercase": "mldsa44:" + strings.ToUpper(keyHex), "prefix-less": keyHex, "alias": "ml-dsa-44:" + keyHex,
		"uppercase prefix": "MLDSA44:" + keyHex, "31 bytes": "mldsa44:" + keyHex[:62], "33 bytes": "mldsa44:" + keyHex + "00",
		"space": " mldsa44:" + keyHex,
	} {
		mutated := authorization
		mutated.Evidence.KeyID = keyID
		if verify(mutated) == nil {
			t.Fatalf("key ID form %q was accepted", name)
		}
	}
	short, _ := NativeAuthorizationSignatureText(make([]byte, mldsa44.SignatureSize))
	for name, value := range map[string]string{
		"padded":            authorization.Evidence.Signature + "=",
		"standard alphabet": "mldsa44:" + std,
		"prefix-less":       encoded,
		"alias":             "ml-dsa-44:" + encoded,
		"uppercase prefix":  "MLDSA44:" + encoded,
		"2419 bytes":        "mldsa44:" + base64.RawURLEncoding.EncodeToString(signature[:mldsa44.SignatureSize-1]),
		"2421 bytes":        "mldsa44:" + base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), signature...), 0)),
		"trailing bits":     "mldsa44:" + trailing,
		"other signature":   short,
	} {
		mutated := authorization
		mutated.Evidence.Signature = value
		if verify(mutated) == nil {
			t.Fatalf("signature form %q was accepted", name)
		}
	}
	if _, err := NativeAuthorizationSignatureText(signature[:100]); err == nil {
		t.Fatal("a 100-byte signature was rendered")
	}
}

// historicalFixture is one consistent proof and observation: a policy with
// Agent-control controller "alpha" alone at the threshold, effective from
// transaction 100 (block time 1000), and a later transaction 200 at block time
// 2000 that the verifier must not examine.
type historicalFixture struct {
	proof       NativeAgentHistoricalAuthorityProofV1
	observation NativeAgentHistoryObservationV1
	expected    NativeAgentAuthorityExpectationV1
	subject     string
	keyID       [mldsa44.KeyIDSize]byte
	at          uint64
}

func testHash(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func testController(t testing.TB, name string, weight, purposes uint32) *nativev1.ControllerV1 {
	t.Helper()
	key := nativeTestFake.PublicKey(name)
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.ControllerV1{KeyId: mldsa44.KeyIDText(id), Mldsa44PublicKey: key, Weight: weight, PurposeMask: purposes,
		Recovery: purposes&nativecore.PurposeRecovery != 0}
}

func newHistoricalFixture(t testing.TB) historicalFixture {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:2", GenesisRootHash: testHash("a"), GenesisFileHash: testHash("b")}
	subject := "agent_" + strings.Repeat("5a", 32)
	account := "0:" + strings.Repeat("c4", 32)
	codeHash := "tvm-cell-sha256:" + strings.Repeat("d5", 32)
	alpha := testController(t, "alpha", 1, nativecore.PurposeAgentControl|nativecore.PurposeDelegation|nativecore.PurposeCapabilityControl)
	recovery := testController(t, "recovery", 1, nativecore.PurposeRecovery)
	keyID, _ := mldsa44.ParseKeyIDText(alpha.KeyId)
	effective := FinalizedTransactionRefV1{LogicalTime: 100, TransactionHash: testHash("1")}
	later := FinalizedTransactionRefV1{LogicalTime: 200, TransactionHash: testHash("2")}
	previous := FinalizedTransactionRefV1{LogicalTime: 50, TransactionHash: testHash("0")}
	proof := NativeAgentHistoricalAuthorityProofV1{SchemaVersion: 1, NetworkID: network.NetworkId,
		GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash, RegistryCodeHash: codeHash,
		AgentAccount: account, EffectiveTransaction: effective,
		EffectiveCheckpoint: FinalizedCheckpointRefV1{Sequence: 10, RootHash: testHash("e"), FileHash: testHash("f")},
		BoundCheckpoint:     FinalizedCheckpointRefV1{Sequence: 20, RootHash: testHash("3"), FileHash: testHash("4")}}
	effectiveTransaction := NativeAgentTransactionV1{Transaction: effective, BlockTimeUnix: 1000, Previous: previous}
	observation := NativeAgentHistoryObservationV1{Network: network, RegistryCodeHash: codeHash, FinalizedSequence: 30,
		BoundCheckpoint: proof.BoundCheckpoint, BoundGenerationUnix: 2100, BoundLastTransaction: later,
		EffectiveCheckpoint: proof.EffectiveCheckpoint, EffectiveAccount: account, EffectiveCodeHash: codeHash,
		EffectiveLastTransaction: effectiveTransaction,
		State: &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{
			AgentId: subject, Policy: &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
				Controllers: []*nativev1.ControllerV1{alpha, recovery}}}}},
		History: []NativeAgentTransactionV1{{Transaction: later, BlockTimeUnix: 2000, Previous: effective}, effectiveTransaction}}
	return historicalFixture{proof: proof, observation: observation, subject: subject, keyID: keyID, at: 1500,
		expected: NativeAgentAuthorityExpectationV1{Network: network, RegistryCodeHash: codeHash, AgentAccount: account}}
}

func (f historicalFixture) check() ([]byte, error) {
	return CheckNativeAgentHistoricalAuthorityV1(f.proof, f.observation, f.expected, f.subject, f.keyID, f.at)
}

func agentState(f *historicalFixture) *nativev1.AgentStateV1 { return f.observation.State.GetAgent() }

// The historical check accepts exactly one consistent observation and refuses
// each element the proof contract requires.
func TestNativeHistoricalAuthorityContract(t *testing.T) {
	base := newHistoricalFixture(t)
	key, err := base.check()
	if err != nil {
		t.Fatalf("consistent observation refused: %v", err)
	}
	if string(key) != string(nativeTestFake.PublicKey("alpha")) {
		t.Fatal("check returned another key")
	}
	// A controller rotated out after the signed time: the later transaction
	// (block time 2000 > 1500) is never examined, so the signature made at
	// 1500 still resolves.
	if _, err := base.check(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*historicalFixture){
		"key absent from the policy": func(f *historicalFixture) {
			other := testController(t, "other", 1, nativecore.PurposeAgentControl)
			f.keyID, _ = mldsa44.ParseKeyIDText(other.KeyId)
		},
		"stored key does not derive its key ID": func(f *historicalFixture) {
			agentState(f).Policy.Controllers[0].Mldsa44PublicKey = nativeTestFake.PublicKey("impostor")
		},
		"no Agent-control purpose": func(f *historicalFixture) {
			agentState(f).Policy.Controllers[0].PurposeMask = nativecore.PurposeDelegation | nativecore.PurposeCapabilityControl
		},
		"delegation only": func(f *historicalFixture) {
			agentState(f).Policy.Controllers[0].PurposeMask = nativecore.PurposeDelegation
		},
		"Capability-control only": func(f *historicalFixture) {
			agentState(f).Policy.Controllers[0].PurposeMask = nativecore.PurposeCapabilityControl
		},
		"recovery only": func(f *historicalFixture) {
			controller := testController(t, "recovery", 1, nativecore.PurposeRecovery)
			f.keyID, _ = mldsa44.ParseKeyIDText(controller.KeyId)
		},
		"weight below the ordinary threshold": func(f *historicalFixture) {
			agentState(f).Policy.Threshold = 2
		},
		"tombstoned": func(f *historicalFixture) { agentState(f).Tombstoned = true },
		"another Agent's state": func(f *historicalFixture) {
			agentState(f).AgentId = "agent_" + strings.Repeat("6b", 32)
		},
		"no typed state": func(f *historicalFixture) { f.observation.State = nil },
		"proof names another network": func(f *historicalFixture) {
			f.proof.GenesisRootHash = testHash("9")
		},
		"reader pinned to another network": func(f *historicalFixture) {
			f.observation.Network = &nativev1.NetworkDomain{NetworkId: "tos:global-id:1",
				GenesisRootHash: testHash("a"), GenesisFileHash: testHash("b")}
		},
		"proof names another registry code": func(f *historicalFixture) {
			f.proof.RegistryCodeHash = "tvm-cell-sha256:" + strings.Repeat("e6", 32)
		},
		"account read with another code": func(f *historicalFixture) {
			f.observation.EffectiveCodeHash = "tvm-cell-sha256:" + strings.Repeat("e6", 32)
		},
		"proof names another account": func(f *historicalFixture) {
			f.proof.AgentAccount = "0:" + strings.Repeat("f7", 32)
		},
		"bound checkpoint beyond finality": func(f *historicalFixture) { f.observation.FinalizedSequence = 19 },
		"bound checkpoint precedes the signed time": func(f *historicalFixture) {
			f.observation.BoundGenerationUnix = 1499
		},
		"bound root substituted": func(f *historicalFixture) { f.observation.BoundCheckpoint.RootHash = testHash("5") },
		"bound file substituted": func(f *historicalFixture) { f.observation.BoundCheckpoint.FileHash = testHash("5") },
		"effective root substituted": func(f *historicalFixture) {
			f.observation.EffectiveCheckpoint.RootHash = testHash("5")
		},
		"effective sequence substituted": func(f *historicalFixture) { f.observation.EffectiveCheckpoint.Sequence = 11 },
		"effective transaction substituted": func(f *historicalFixture) {
			f.observation.EffectiveLastTransaction.Transaction.TransactionHash = testHash("6")
		},
		"effective transaction after the signed time": func(f *historicalFixture) {
			f.observation.EffectiveLastTransaction.BlockTimeUnix = 1501
			f.observation.History[1].BlockTimeUnix = 1501
		},
		"history head is not the bound account's last transaction": func(f *historicalFixture) {
			f.observation.BoundLastTransaction = FinalizedTransactionRefV1{LogicalTime: 300, TransactionHash: testHash("7")}
		},
		"history lacks the effective transaction": func(f *historicalFixture) {
			f.observation.History = f.observation.History[:1]
		},
		"history is discontinuous": func(f *historicalFixture) {
			f.observation.History[0].Previous = FinalizedTransactionRefV1{LogicalTime: 99, TransactionHash: testHash("8")}
		},
		"a later transaction at or before the signed time is skipped": func(f *historicalFixture) {
			f.observation.History[0].BlockTimeUnix = 1500
		},
		"empty history": func(f *historicalFixture) { f.observation.History = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newHistoricalFixture(t)
			mutate(&fixture)
			if _, err := fixture.check(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
	// Signing after the controller was removed: at 2500 the effective
	// transaction is the rotation (lt 200), whose state no longer names alpha.
	removed := newHistoricalFixture(t)
	rotation := removed.observation.History[0]
	removed.at = 2500
	removed.proof.EffectiveTransaction = rotation.Transaction
	removed.observation.EffectiveLastTransaction = rotation
	removed.observation.BoundGenerationUnix = 2600
	removed.observation.History = []NativeAgentTransactionV1{rotation}
	if _, err := removed.check(); err != nil {
		t.Fatalf("the rotation state itself was refused before the removal: %v", err)
	}
	agentState(&removed).Policy.Controllers = agentState(&removed).Policy.Controllers[1:]
	if _, err := removed.check(); err == nil {
		t.Fatal("a signature made after the controller's removal resolved")
	}
	// The same post-removal signature cannot reach back to the old state: the
	// old effective transaction is no longer the last one at or before 2500.
	stale := newHistoricalFixture(t)
	stale.at = 2500
	stale.observation.BoundGenerationUnix = 2600
	if _, err := stale.check(); err == nil {
		t.Fatal("a stale effective state was accepted past a later transaction")
	}
}

// The proof travels as exact canonical CBOR; anything else fails closed.
func TestNativeHistoricalProofEncodingIsExact(t *testing.T) {
	fixture := newHistoricalFixture(t)
	encoded, err := EncodeNativeAgentHistoricalAuthorityProofV1(fixture.proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeAgentHistoricalAuthorityProofV1(encoded)
	if err != nil || decoded != fixture.proof {
		t.Fatalf("canonical proof did not decode: %v", err)
	}
	generic := map[string]any{}
	if err := json.Unmarshal(mustJSON(t, fixture.proof), &generic); err != nil {
		t.Fatal(err)
	}
	withExtra := map[string]any{}
	for k, v := range generic {
		withExtra[k] = v
	}
	withExtra["key"] = "attacker"
	withoutField := map[string]any{}
	for k, v := range generic {
		if k != "bound_checkpoint" {
			withoutField[k] = v
		}
	}
	for name, value := range map[string]any{"unknown field": withExtra, "missing field": withoutField} {
		raw, err := codec.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeNativeAgentHistoricalAuthorityProofV1(raw); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	for name, raw := range map[string][]byte{
		"trailing byte": append(append([]byte(nil), encoded...), 0), "empty": nil,
		"oversized": make([]byte, MaxHistoricalAuthorityProofBytes+1),
	} {
		if _, err := DecodeNativeAgentHistoricalAuthorityProofV1(raw); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	for name, mutate := range map[string]func(*NativeAgentHistoricalAuthorityProofV1){
		"schema version 2":           func(p *NativeAgentHistoricalAuthorityProofV1) { p.SchemaVersion = 2 },
		"uppercase account":          func(p *NativeAgentHistoricalAuthorityProofV1) { p.AgentAccount = strings.ToUpper(p.AgentAccount) },
		"masterchain account":        func(p *NativeAgentHistoricalAuthorityProofV1) { p.AgentAccount = "-1:" + p.AgentAccount[2:] },
		"effective after bound":      func(p *NativeAgentHistoricalAuthorityProofV1) { p.EffectiveCheckpoint.Sequence = 21 },
		"zero logical time":          func(p *NativeAgentHistoricalAuthorityProofV1) { p.EffectiveTransaction.LogicalTime = 0 },
		"code hash without its type": func(p *NativeAgentHistoricalAuthorityProofV1) { p.RegistryCodeHash = testHash("d") },
	} {
		proof := fixture.proof
		mutate(&proof)
		if _, err := EncodeNativeAgentHistoricalAuthorityProofV1(proof); err == nil {
			t.Fatalf("%s was encoded", name)
		}
		raw, err := codec.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeNativeAgentHistoricalAuthorityProofV1(raw); err == nil {
			t.Fatalf("%s was decoded", name)
		}
	}
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type staticHistoryReader struct {
	observation NativeAgentHistoryObservationV1
	subjects    []string
}

func (r *staticHistoryReader) ReadNativeAgentHistory(_ context.Context, _ NativeAgentHistoricalAuthorityProofV1,
	subject string) (NativeAgentHistoryObservationV1, error) {
	r.subjects = append(r.subjects, subject)
	return r.observation, nil
}

func testRegistryLocator(t testing.TB, network *nativev1.NetworkDomain) *nativecore.Locator {
	t.Helper()
	raw, err := os.ReadFile("../nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CodeHash string `json:"contract_code_hash"`
		CodeBOC  string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	locator, err := nativecore.NewLocator(network, 0, vectors.CodeBOC, vectors.CodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return locator
}

// The resolver derives the account and code from its own Registry locator,
// never from the proof, and hands the check the subject's reads.
func TestNativeAgentAuthorityResolverPinsTheRegistryDerivation(t *testing.T) {
	fixture := newHistoricalFixture(t)
	locator := testRegistryLocator(t, fixture.expected.Network)
	identity, err := locator.Locate(fixture.subject)
	if err != nil {
		t.Fatal(err)
	}
	fixture.proof.AgentAccount, fixture.observation.EffectiveAccount = identity.Address, identity.Address
	fixture.proof.RegistryCodeHash = identity.CodeHash
	fixture.observation.RegistryCodeHash, fixture.observation.EffectiveCodeHash = identity.CodeHash, identity.CodeHash
	encoded, err := EncodeNativeAgentHistoricalAuthorityProofV1(fixture.proof)
	if err != nil {
		t.Fatal(err)
	}
	reader := &staticHistoryReader{observation: fixture.observation}
	resolver := NativeAgentAuthorityResolverV1{Reader: reader, Locator: locator, Signatures: nativeTestFake}
	scope := AuthorityResolutionScopeV1{AuthoritySubject: fixture.subject}
	at := time.Unix(int64(fixture.at), 0)
	key, err := resolver.ResolveNativeAgentKey(scope, fixture.keyID, at, encoded)
	if err != nil || string(key) != string(nativeTestFake.PublicKey("alpha")) {
		t.Fatalf("resolver refused a consistent proof: %v", err)
	}
	if len(reader.subjects) != 1 || reader.subjects[0] != fixture.subject {
		t.Fatalf("reader was asked for %v", reader.subjects)
	}
	other := "agent_" + strings.Repeat("6b", 32)
	if _, err := resolver.ResolveNativeAgentKey(AuthorityResolutionScopeV1{AuthoritySubject: other}, fixture.keyID, at, encoded); err == nil {
		t.Fatal("a proof for another subject's account resolved")
	}
	// A proof and reads naming another account, consistent with each other
	// and holding the subject's state, are refused: the account is the
	// Registry's derivation for the subject, never the proof's.
	elsewhereAccount := fixture
	elsewhereAccount.proof.AgentAccount = "0:" + strings.Repeat("f7", 32)
	elsewhereAccount.observation.EffectiveAccount = elsewhereAccount.proof.AgentAccount
	elsewhereEncoded, err := EncodeNativeAgentHistoricalAuthorityProofV1(elsewhereAccount.proof)
	if err != nil {
		t.Fatal(err)
	}
	moved := NativeAgentAuthorityResolverV1{Reader: &staticHistoryReader{observation: elsewhereAccount.observation},
		Locator: locator, Signatures: nativeTestFake}
	if _, err := moved.ResolveNativeAgentKey(scope, fixture.keyID, at, elsewhereEncoded); err == nil {
		t.Fatal("a proof naming another account than the subject's Registry account resolved")
	}
	if _, err := resolver.ResolveNativeAgentKey(scope, fixture.keyID, at, []byte("not a proof")); err == nil {
		t.Fatal("an undecodable proof resolved")
	}
	elsewhere := NativeAgentAuthorityResolverV1{Reader: reader, Signatures: nativeTestFake,
		Locator: testRegistryLocator(t, &nativev1.NetworkDomain{NetworkId: "tos:global-id:1",
			GenesisRootHash: testHash("a"), GenesisFileHash: testHash("b")})}
	if _, err := elsewhere.ResolveNativeAgentKey(scope, fixture.keyID, at, encoded); err == nil {
		t.Fatal("a resolver pinned to another network accepted the proof")
	}
	if _, err := (NativeAgentAuthorityResolverV1{}).ResolveNativeAgentKey(scope, fixture.keyID, at, encoded); err == nil {
		t.Fatal("an unconfigured resolver resolved")
	}
}

// Stage admission stays on the Action Authority's Ed25519 scheme: native
// ML-DSA-44 evidence does not decode there, and an Ed25519 admission
// authorization keeps verifying.
func TestStageAdmissionIsNeverNativeEvidence(t *testing.T) {
	native := testSignAuthorization(t, vectorStatement, vectorStatementDomain, "stage", []byte("proof"))
	encoded, err := codec.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	var stage StageActionAdmissionAuthorizationV1
	if err := codec.Unmarshal(encoded, &stage); err == nil {
		t.Fatal("native ML-DSA-44 evidence decoded as a stage admission authorization")
	}
	fixture := newStageAdmissionFixture(t)
	admission := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
	now := fixture.now()
	if err := fixture.verify(admission); err != nil {
		t.Fatalf("Ed25519 stage admission refused: %v", err)
	}
	if err := VerifyObjectAuthorization(ProfileQualifiedObjectAuthorizationV1{AuthoritySubject: admission.AuthoritySubject,
		ProfileURI: admission.ProfileURI, ProfileVersion: admission.ProfileVersion, ProfileDigest: admission.ProfileDigest,
		AuthorizedObjectKind: admission.AuthorizedObjectKind, AuthorizedBodyDigest: admission.AuthorizedBodyDigest,
		ValidationTimeUnix: admission.ValidationTimeUnix, EvidenceContentType: NativeAuthorizationContentType,
		Evidence: NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: admission.Evidence.PublicKey,
			Signature: admission.Evidence.Signature, HistoricalAuthorityProof: []byte("proof")}},
		admission.AuthorizedObjectKind, admission.AuthorizedBodyDigest, StageActionAdmissionSignatureDomain,
		allowAuthorityResolver{}, now); err == nil {
		t.Fatal("an Ed25519 Action Authority signature verified as native evidence")
	}
	// The stage wire layout is unchanged: the same field names as before.
	var fields map[string]any
	if err := json.Unmarshal(mustJSON(t, admission.Evidence), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["public_key"] == nil || fields["signature"] == nil || fields["historical_authority_proof"] == nil {
		t.Fatalf("stage evidence fields changed: %v", fields)
	}
}
