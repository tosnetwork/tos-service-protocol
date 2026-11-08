package agentguarantor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// measuredDecisionReceiptPath is a complete authorized claim-decision
// admission receipt produced by a full Guarantor provider flow with ML-DSA-44
// authority (test identities only). Its canonical size is 1,068,868 bytes,
// which the 1 MiB ceiling refused.
const measuredDecisionReceiptPath = "testdata/claim-decision-admission-receipt-mldsa44.json.gz"

const measuredDecisionReceiptBytes = 1_068_868

// referenceMaximumAdmittedClaimEnvelopeBytes is the reference released
// profile's maximum admitted claim envelope.
const referenceMaximumAdmittedClaimEnvelopeBytes = 64 << 10

func loadMeasuredDecisionReceipt(t *testing.T) AuthorizedClaimDecisionAdmissionReceiptV1 {
	t.Helper()
	file, err := os.Open(measuredDecisionReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var receipt AuthorizedClaimDecisionAdmissionReceiptV1
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func mustCanonicalSize(t *testing.T, value any) int {
	t.Helper()
	encoded, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return len(encoded)
}

func toJSONModel(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model any
	if err := decoder.Decode(&model); err != nil {
		t.Fatal(err)
	}
	return model
}

func fromJSONModel(t *testing.T, model any, output any) {
	t.Helper()
	raw, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, output); err != nil {
		t.Fatal(err)
	}
}

// rewriteNested applies change to every map of the JSON data model,
// including those inside base64 text that holds a canonical Guarantor
// object (the nested stage requests), and re-encodes those bottom up.
func rewriteNested(t *testing.T, value any, change func(map[string]any)) any {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = rewriteNested(t, item, change)
		}
		change(typed)
		return typed
	case []any:
		for index := range typed {
			typed[index] = rewriteNested(t, typed[index], change)
		}
		return typed
	case string:
		if len(typed) < 256 {
			return typed
		}
		raw, err := base64.StdEncoding.DecodeString(typed)
		if err != nil {
			return typed
		}
		var inner any
		if Unmarshal(raw, &inner) != nil {
			return typed
		}
		encoded, err := Canonical(rewriteNested(t, inner, change))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(encoded)
	}
	return value
}

func sizeTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

// buildWorstCaseAuthorizedDecisionReceipt starts from the measured receipt
// and drives every size dimension of the authorized-decision path to its
// reference-profile maximum: the claim envelope at the admitted maximum
// (replaced at every nested copy), a successor decision with its predecessor
// claim-state transition receipt (whose decision proof repeats the maximum
// claim and the decision), the prior pending application token, every
// optional body field, two payout lines, and descriptor-only evidence. The
// result is shaped, not signed: signature and key lengths are the real
// ML-DSA-44 lengths taken from the measured receipt.
func buildWorstCaseAuthorizedDecisionReceipt(t *testing.T) AuthorizedClaimDecisionAdmissionReceiptV1 {
	t.Helper()
	receipt := loadMeasuredDecisionReceipt(t)
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	item := OtherRecoveryItemV1{RecoveryItemID: strings.Repeat("r", 120), SourceKind: strings.Repeat("k", 120),
		SourceSubject: strings.Repeat("a", 120), RelatedInstrumentDigest: sizeTestDigest("e"),
		RecoveryStatus: strings.Repeat("s", 60), AmountReceived: claim.Body.ClaimedAmount,
		AmountReceivable: claim.Body.ClaimedAmount}
	for {
		next := claim
		next.OtherRecoveryDeclaration.RecoveryItems = append(append([]OtherRecoveryItemV1(nil),
			claim.OtherRecoveryDeclaration.RecoveryItems...), item)
		if mustCanonicalSize(t, next) > referenceMaximumAdmittedClaimEnvelopeBytes {
			break
		}
		claim = next
	}
	// Close the remaining gap with a short item whose bounded text fields
	// (at most 128 characters each) grow one character at a time.
	small := OtherRecoveryItemV1{RecoveryItemID: "r", SourceKind: "k", SourceSubject: "a", RecoveryStatus: "s",
		AmountReceived: claim.Body.ClaimedAmount, AmountReceivable: claim.Body.ClaimedAmount}
	if next := claim; true {
		next.OtherRecoveryDeclaration.RecoveryItems = append(append([]OtherRecoveryItemV1(nil),
			claim.OtherRecoveryDeclaration.RecoveryItems...), small)
		if mustCanonicalSize(t, next) <= referenceMaximumAdmittedClaimEnvelopeBytes {
			claim = next
		}
	}
	last := &claim.OtherRecoveryDeclaration.RecoveryItems[len(claim.OtherRecoveryDeclaration.RecoveryItems)-1]
	for _, field := range []*string{&last.RecoveryItemID, &last.SourceKind, &last.SourceSubject, &last.RecoveryStatus} {
		for len(*field) < 128 && mustCanonicalSize(t, claim) < referenceMaximumAdmittedClaimEnvelopeBytes {
			*field += "x"
		}
		if mustCanonicalSize(t, claim) > referenceMaximumAdmittedClaimEnvelopeBytes {
			*field = (*field)[:len(*field)-1]
		}
	}
	claimModel := toJSONModel(t, claim)
	claimID := claim.Body.ClaimID
	model := rewriteNested(t, toJSONModel(t, receipt), func(node map[string]any) {
		candidate, ok := node["authorized_claim"].(map[string]any)
		if !ok {
			return
		}
		if body, ok := candidate["body"].(map[string]any); ok && body["claim_id"] == claimID {
			node["authorized_claim"] = claimModel
		}
	})
	fromJSONModel(t, model, &receipt)

	descriptorItems := func(count int) []CanonicalGuarantorEvidenceItemV1 {
		items := make([]CanonicalGuarantorEvidenceItemV1, 0, count)
		for index := 0; index < count; index++ {
			digest := sizeTestDigest(string("0123456789"[index]))
			items = append(items, CanonicalGuarantorEvidenceItemV1{
				ContentType: GuarantorMediaTypePrefixV1 + "claim-decision-admission.v1+cbor", EvidenceProfileDigest: sizeTestDigest("d"),
				EvidenceEnvelopeDigest: digest, Representation: "content_addressed",
				ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: GuarantorMediaTypePrefixV1 + "claim-decision-admission.v1+cbor",
					ContentDigest: digest, ContentSize: MaxCanonicalObjectBytes, RetrievalPolicyDigest: sizeTestDigest("d")}})
		}
		return items
	}
	const evidenceItems = 4 // reference profile MaximumEvidenceItems
	decision := receipt.AuthorizedClaimDecision
	for len(decision.Body.PayoutLines) > 0 && len(decision.Body.PayoutLines) < 2 {
		decision.Body.PayoutLines = append(decision.Body.PayoutLines, decision.Body.PayoutLines[0])
	}
	decision.DecisionEvidenceSet.Items = descriptorItems(evidenceItems)
	receipt.AuthorizedClaimDecision = decision

	evidenceSet := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-challenge-close",
		ContextDigest: sizeTestDigest("c"), Items: descriptorItems(evidenceItems)}
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "claim-challenge-close",
		CoverageAgreementBodyDigest: receipt.Body.CoverageAgreementBodyDigest, ObligationID: receipt.Body.CoverageObligationID,
		ClaimID: claimID, TargetState: "reviewing"}
	for index := 0; index < evidenceItems; index++ {
		projection.EvidenceDigests = append(projection.EvidenceDigests, TransitionEvidenceDigestRefV1{
			EvidenceRole: "challenge-evidence", DigestKind: "evidence-envelope", ObjectDigest: sizeTestDigest(string("0123456789"[index]))})
	}
	body := receipt.Body
	action := ClaimStateTransitionActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest,
		CoverageObligationID: body.CoverageObligationID, ClaimID: claimID, TransitionKind: "challenge_admission",
		ExpectedClaimStateRevision: body.AdmittedClaimStateRevision, TargetState: "reviewing", ExpectedChallengeRoundsUsed: 0,
		TargetChallengeRoundsUsed: 1, SuccessorDecisionDueAtUnix: body.AdmittedAtUnix + 3600,
		AuthorizedClaimDecisionAdmissionReceiptDigest: sizeTestDigest("a"), TransitionEvidenceProjection: projection,
		TransitionEvidenceSet: evidenceSet}
	request, err := Canonical(action)
	if err != nil {
		t.Fatal(err)
	}
	stage := receipt.StageActionAdmissionEvidence
	stage.CanonicalRequest = request
	transition := AuthorizedClaimStateTransitionReceiptV1{
		Body: ClaimStateTransitionReceiptBodyV1{SchemaVersion: 1, AuthorityID: body.AuthorityID,
			CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest, CoverageObligationID: body.CoverageObligationID,
			ClaimID: claimID, TransitionKind: "challenge_admission", TransitionEvidenceProjectionDigest: sizeTestDigest("1"),
			AuthorizedActionDigest: body.AuthorizedActionDigest, StableActionID: body.StableActionID,
			ExactRequestDigest: body.ExactRequestDigest, WriterGeneration: body.WriterGeneration,
			WriterFenceDigest: body.WriterFenceDigest, PriorClaimState: "approved", ResultingClaimState: "reviewing",
			PriorClaimStateRevision: body.AdmittedClaimStateRevision, ResultingClaimStateRevision: body.AdmittedClaimStateRevision + 1,
			ChallengeRoundsUsedAfter: 1, SuccessorDecisionDueAtUnix: body.AdmittedAtUnix + 3600,
			TransitionedAtUnix: body.AdmittedAtUnix + 60, AuthorityAdmissionEligibilityProofSetDigest: sizeTestDigest("2")},
		StageActionAdmissionEvidence: stage,
		DecisionAdmissionProof: ClaimDecisionAdmissionReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: sizeTestDigest("3"),
			ReceiptDescriptor: ImmutableEvidenceDescriptorV1{ContentType: GuarantorMediaTypePrefixV1 + "claim-decision-admission.v1+cbor",
				ContentDigest: sizeTestDigest("3"), ContentSize: MaxCanonicalObjectBytes, RetrievalPolicyDigest: sizeTestDigest("4")},
			ReceiptBody: body, CoverageEndCommitment: receipt.CoverageEndCommitment, AuthorizedClaimDecision: decision,
			AuthorizedClaim: claim, ReceiptAuthorizations: receipt.Authorizations,
			SealBody: ClaimDecisionAdmissionReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: sizeTestDigest("3"),
				ReceiptBodyDigest: sizeTestDigest("5"), AuthorizedActionDigest: body.AuthorizedActionDigest,
				AuthorizedClaimDecisionDigest: body.AuthorizedClaimDecisionDigest, AuthorizedClaimEnvelopeDigest: sizeTestDigest("6"),
				CoverageEndCommitmentDigest: sizeTestDigest("7"), CoverageTermsDigest: sizeTestDigest("8"),
				SealedAtUnix: body.AdmittedAtUnix + 1},
			SealAuthorization: receipt.Authorizations[0]},
		TransitionEvidenceProjection: projection, TransitionEvidenceSet: evidenceSet,
		AuthorityAdmissionEligibilityProofSet: receipt.AuthorityAdmissionEligibilityProofSet,
		Authorizations:                        receipt.Authorizations}
	receipt.PredecessorClaimStateTransitionReceipt = &transition
	token := DecisionApplicationTokenV1{SchemaVersion: 1, TokenID: sizeTestDigest("9"),
		CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest, CoverageObligationID: body.CoverageObligationID,
		ClaimID: claimID, AuthorizedClaimDecisionDigest: body.AuthorizedClaimDecisionDigest, DecisionSequence: 3,
		DecisionRevision: 3, ReservedApprovedAmount: body.AggregatePendingDecisionReserveAfter, TokenRevision: 2, State: "superseded"}
	receipt.PriorPendingApplicationToken = &token
	if receipt.Body.ResultingApplicationToken == nil {
		receipt.Body.ResultingApplicationToken = &token
	}
	receipt.Body.DecisionSequence, receipt.Body.DecisionRevision, receipt.Body.DecisionPath = 4, 4, "successor"
	receipt.Body.PredecessorDecisionAdmissionReceiptDigest = sizeTestDigest("3")
	receipt.Body.PredecessorClaimStateTransitionReceiptDigest = sizeTestDigest("b")
	receipt.Body.PriorApplicationTokenDigest, receipt.Body.PriorApplicationTokenTerminalState = sizeTestDigest("c"), "superseded"
	receipt.Body.ChallengeStartsAtUnix, receipt.Body.ChallengeEndsAtUnix = body.AdmittedAtUnix, body.AdmittedAtUnix+3600
	receipt.Body.ResolutionStartsAtUnix, receipt.Body.ResolutionDueAtUnix = body.AdmittedAtUnix, body.AdmittedAtUnix+7200
	var admission ClaimDecisionAdmissionActionBodyV1
	if err := Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &admission); err != nil ||
		admission.AuthorizedDecisionVariant == nil {
		t.Fatalf("measured decision request is not an authorized-decision request: %v", err)
	}
	admission.AuthorizedDecisionVariant.PredecessorDecisionAdmissionReceiptDigest = sizeTestDigest("3")
	admission.AuthorizedDecisionVariant.PredecessorClaimStateTransitionReceiptDigest = sizeTestDigest("b")
	if receipt.StageActionAdmissionEvidence.CanonicalRequest, err = Canonical(admission); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func largestNestedString(t *testing.T, value any) int {
	t.Helper()
	largest := 0
	rewriteNested(t, toJSONModel(t, value), func(node map[string]any) {
		for _, item := range node {
			if text, ok := item.(string); ok && len(text) > largest {
				largest = len(text)
			}
		}
	})
	return largest
}

func TestMeasuredDecisionReceiptFitsTheGuarantorCeiling(t *testing.T) {
	receipt := loadMeasuredDecisionReceipt(t)
	encoded, err := Canonical(receipt)
	if err != nil {
		t.Fatalf("measured receipt refused: %v", err)
	}
	if len(encoded) != measuredDecisionReceiptBytes {
		t.Fatalf("measured receipt is %d bytes, want %d", len(encoded), measuredDecisionReceiptBytes)
	}
	if _, err := ClaimDecisionAdmissionReceiptDigestV1(receipt); err != nil {
		t.Fatalf("measured receipt digest refused: %v", err)
	}
	decoded, err := DecodeRegisteredObjectV1("claim-decision-admission-receipt", encoded)
	if err != nil {
		t.Fatalf("measured receipt decode refused: %v", err)
	}
	again, err := Canonical(decoded)
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatal("measured receipt does not re-encode identically")
	}
}

func TestWorstCaseAuthorizedDecisionReceiptFitsWithMargin(t *testing.T) {
	receipt := buildWorstCaseAuthorizedDecisionReceipt(t)
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	if size := mustCanonicalSize(t, claim); size > referenceMaximumAdmittedClaimEnvelopeBytes ||
		size < referenceMaximumAdmittedClaimEnvelopeBytes-256 {
		t.Fatalf("worst-case claim envelope is %d bytes, want the %d-byte maximum", size, referenceMaximumAdmittedClaimEnvelopeBytes)
	}
	encoded, err := Canonical(receipt)
	if err != nil {
		t.Fatalf("worst-case authorized-decision receipt refused: %v", err)
	}
	if _, err := DecodeRegisteredObjectV1("claim-decision-admission-receipt", encoded); err != nil {
		t.Fatalf("worst-case receipt decode refused: %v", err)
	}
	if len(encoded) <= measuredDecisionReceiptBytes {
		t.Fatalf("worst case %d is not larger than the measured receipt", len(encoded))
	}
	longest := largestNestedString(t, receipt)
	request := len(receipt.AuthorizedClaimAdmissionReceipt.StageActionAdmissionEvidence.CanonicalRequest)
	t.Logf("worst-case authorized-decision receipt: %d bytes; ceiling %d; margin %d (%.1f%%); longest nested string %d; claim admission request %d",
		len(encoded), MaxCanonicalObjectBytes, MaxCanonicalObjectBytes-len(encoded),
		100*float64(MaxCanonicalObjectBytes-len(encoded))/float64(MaxCanonicalObjectBytes), longest, request)
	if longest <= codec.MaxStringBytes {
		t.Fatalf("worst case no longer needs the Guarantor string limit (%d)", longest)
	}
	if request > MaximumStageRequestBytesV1 {
		t.Fatalf("worst-case claim admission request %d exceeds the stage request ceiling", request)
	}
}

// padToCanonicalSize grows one text field of receipt until its canonical
// encoding is exactly size bytes.
func padToCanonicalSize(t *testing.T, receipt AuthorizedClaimDecisionAdmissionReceiptV1, size int) AuthorizedClaimDecisionAdmissionReceiptV1 {
	t.Helper()
	receipt.Body.PriorApplicationTokenTerminalState = ""
	base := mustCanonicalSize(t, receipt)
	// A text string longer than 65,535 bytes has a fixed 5-byte header, so
	// one more character is exactly one more canonical byte.
	padding := size - base - 5 - 65_536
	if padding < 0 {
		t.Fatalf("worst case %d is too close to %d to pad", base, size)
	}
	receipt.Body.PriorApplicationTokenTerminalState = strings.Repeat("p", 65_536)
	receipt.Body.PriorApplicationTokenTerminalState += strings.Repeat("p", padding)
	for current := mustCanonicalSizeOrZero(receipt); current != size; current = mustCanonicalSizeOrZero(receipt) {
		if current == 0 || current > size {
			receipt.Body.PriorApplicationTokenTerminalState = receipt.Body.PriorApplicationTokenTerminalState[1:]
		} else {
			receipt.Body.PriorApplicationTokenTerminalState += "p"
		}
	}
	return receipt
}

func mustCanonicalSizeOrZero(value any) int {
	encoded, err := codec.Bounded{Limits: codec.Limits{CanonicalBytes: 2 * MaxCanonicalObjectBytes,
		JSONBytes: 4 * MaxCanonicalObjectBytes, StringBytes: MaxCanonicalObjectBytes}}.Marshal(value)
	if err != nil {
		return 0
	}
	return len(encoded)
}

func TestGuarantorCeilingIsExact(t *testing.T) {
	worst := buildWorstCaseAuthorizedDecisionReceipt(t)
	atLimit := padToCanonicalSize(t, worst, MaxCanonicalObjectBytes)
	encoded, err := Canonical(atLimit)
	if err != nil || len(encoded) != MaxCanonicalObjectBytes {
		t.Fatalf("a %d-byte Guarantor object was refused: len=%d err=%v", MaxCanonicalObjectBytes, len(encoded), err)
	}
	var decoded AuthorizedClaimDecisionAdmissionReceiptV1
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("a %d-byte Guarantor object failed to decode: %v", MaxCanonicalObjectBytes, err)
	}
	overLimit := padToCanonicalSize(t, worst, MaxCanonicalObjectBytes+1)
	if _, err := Canonical(overLimit); err == nil {
		t.Fatal("a Guarantor object one byte over the ceiling was encoded")
	}
	if _, err := Digest(ClaimDecisionAdmissionReceiptDomainV1, overLimit); err == nil {
		t.Fatal("a Guarantor object one byte over the ceiling was digested")
	}
	over, err := codec.Bounded{Limits: codec.Limits{CanonicalBytes: 2 * MaxCanonicalObjectBytes,
		JSONBytes: 4 * MaxCanonicalObjectBytes, StringBytes: MaxCanonicalObjectBytes}}.Marshal(overLimit)
	if err != nil || len(over) != MaxCanonicalObjectBytes+1 {
		t.Fatalf("could not build the over-limit bytes: len=%d err=%v", len(over), err)
	}
	if err := Unmarshal(over, &decoded); err == nil {
		t.Fatal("a Guarantor object one byte over the ceiling was decoded")
	}
	if _, err := DecodeRegisteredObjectV1("claim-decision-admission-receipt", over); err == nil {
		t.Fatal("the registered decoder accepted an object one byte over the ceiling")
	}
}

func TestNonGuarantorObjectsKeepTheGlobalLimit(t *testing.T) {
	receipt := loadMeasuredDecisionReceipt(t)
	if _, err := codec.Marshal(receipt); err == nil {
		t.Fatal("the global codec encoded a value over 1 MiB")
	}
	if _, err := codec.Digest(ClaimDecisionAdmissionReceiptDomainV1, receipt); err == nil {
		t.Fatal("the global codec digested a value over 1 MiB")
	}
	encoded, err := Canonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := codec.Unmarshal(encoded, &generic); err == nil {
		t.Fatal("the global codec decoded a value over 1 MiB")
	}
	agreement := agentcommerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:large", Version: 1,
		NetworkContext: "tos:test", TermsContentType: "text/plain", Terms: bytes.Repeat([]byte("t"), 900<<10)}
	if _, err := agentcommerce.AgreementBodyDigest(agreement); err == nil {
		t.Fatal("a commerce Agreement over 1 MiB was digested")
	}
	agreementBytes, err := Canonical(agreement)
	if err != nil || len(agreementBytes) <= codec.MaxCanonicalBytes {
		t.Fatalf("could not build an over-1-MiB Agreement: len=%d err=%v", len(agreementBytes), err)
	}
	if _, err := DecodeRegisteredObjectV1("coverage-agreement", agreementBytes); err == nil {
		t.Fatal("the Guarantor registry widened the commerce Agreement bound")
	}
	event := agentcommerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: ProfileURI, ProfileVersion: 1,
		ObjectKind: "claim", ObjectContentType: "application/vnd.tos.service.agent-guarantor-claim.v1+cbor",
		ObjectDigest: sizeTestDigest("a"), ObjectSizeBytes: 1, CarriageKind: "inline",
		CanonicalObjectBytes: bytes.Repeat([]byte{0xa0}, 1), CreatedAtUnix: 1, ExpiresAtUnix: 2,
		ObligationIDs: []string{strings.Repeat("o", 1100<<10)}}
	eventBytes, err := Canonical(event)
	if err != nil || len(eventBytes) <= codec.MaxCanonicalBytes {
		t.Fatalf("could not build an over-1-MiB commerce event: len=%d err=%v", len(eventBytes), err)
	}
	if _, err := DecodeRegisteredObjectV1("commerce-profile-event", eventBytes); err == nil {
		t.Fatal("the Guarantor registry widened the commerce profile event bound")
	}
}

func TestRegisteredKindsChooseTheirOwningProfileLimits(t *testing.T) {
	for kind, factory := range guarantorObjectFactoriesV1() {
		value := factory()
		typeOf := reflect.TypeOf(value).Elem()
		got := registeredObjectCodecV1(value).Limits
		want := codec.DefaultLimits()
		if typeOf.PkgPath() == guarantorPackagePath {
			want = GuarantorCodecLimitsV1
		}
		if got != want {
			t.Fatalf("kind %s (%s) uses limits %+v, want %+v", kind, typeOf, got, want)
		}
	}
	for key, factory := range guarantorMutationFactoriesV1() {
		if reflect.TypeOf(factory()).Elem().PkgPath() != guarantorPackagePath {
			t.Fatalf("mutation %v decodes a type of another profile; give it that profile's limits", key)
		}
	}
	if MaxCanonicalObjectBytes != agentcommerce.MaxProfileEventObjectBytes {
		t.Fatal("the commerce profile-event object bound differs from the Guarantor ceiling")
	}
}

func TestGuarantorEvidenceIsDescriptorOnly(t *testing.T) {
	inline := func(contentType string) CanonicalGuarantorEvidenceSetV1 {
		return CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-decision-evidence",
			ContextDigest: sizeTestDigest("a"), Items: []CanonicalGuarantorEvidenceItemV1{{ContentType: contentType,
				EvidenceProfileDigest: sizeTestDigest("b"), EvidenceEnvelopeDigest: sizeTestDigest("c"),
				Representation: "inline", CanonicalEnvelopeBytes: []byte{0xa0}}}}
	}
	types := []string{GuarantorNoPayoutMarkerContentTypeV1, GuarantorPayoutExecutionContentTypeV1,
		CollateralEvidenceContentTypeV1, CollateralControlEvidenceContentTypeV1, OperationalIndependenceEvidenceContentTypeV1,
		GuarantorMediaTypePrefixV1 + "claim-filing-close-envelope.v1+cbor",
		GuarantorMediaTypePrefixV1 + "claim-terminal-resolution-bundle.v1+cbor"}
	for _, entry := range ReleasedCommerceCarriageObjectsV1() {
		types = append(types, entry.ContentType)
	}
	for _, contentType := range types {
		if err := ValidateCanonicalGuarantorEvidenceSetV1(inline(contentType)); err == nil {
			t.Fatalf("inline evidence of Guarantor media type %s was accepted", contentType)
		}
	}
	if err := ValidateCanonicalGuarantorEvidenceSetV1(inline("application/vnd.example.adapter-receipt+cbor")); err != nil {
		t.Fatalf("inline external evidence was refused: %v", err)
	}
	set := inline(GuarantorPayoutExecutionContentTypeV1)
	set.Items[0].Representation, set.Items[0].CanonicalEnvelopeBytes = "content_addressed", nil
	set.Items[0].ImmutableDescriptor = &ImmutableEvidenceDescriptorV1{ContentType: GuarantorPayoutExecutionContentTypeV1,
		ContentDigest: sizeTestDigest("c"), ContentSize: MaxCanonicalObjectBytes, RetrievalPolicyDigest: sizeTestDigest("b")}
	if err := ValidateCanonicalGuarantorEvidenceSetV1(set); err != nil {
		t.Fatalf("descriptor evidence of a Guarantor media type was refused: %v", err)
	}
}

type permissiveAgreementVerifier struct{}

func (permissiveAgreementVerifier) VerifyAgreementEvidence(agentcommerce.AgreementAuthorizationEvidence, time.Time) error {
	return nil
}

func TestAuthorizedDecisionRefusesFallbackOnlyFields(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	const want = "late filing-close receipt or fallback cutoff"
	cases := map[string]func(*AuthorizedClaimDecisionAdmissionReceiptV1){
		"arbitrary filing-close receipt": func(receipt *AuthorizedClaimDecisionAdmissionReceiptV1) {
			receipt.LateFilingCloseReceipt = &AuthorizedClaimFilingCloseReceiptV1{}
		},
		"filing-close digest only": func(receipt *AuthorizedClaimDecisionAdmissionReceiptV1) {
			receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("f")
		},
		"fallback cutoff": func(receipt *AuthorizedClaimDecisionAdmissionReceiptV1) {
			receipt.Body.FallbackTriggerCutoffUnix = 1
		},
	}
	for name, change := range cases {
		receipt := loadMeasuredDecisionReceipt(t)
		change(&receipt)
		err := VerifyClaimDecisionAdmissionReceiptV1(receipt, terms, permissiveAgreementVerifier{}, allowAuthorityResolver{}, nil, now)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: authorized decision admission was not refused for its fallback-only field: %v", name, err)
		}
	}
}

func TestReleasedSizeVectorsAreExactBoundaries(t *testing.T) {
	vectors, err := ReleasedSizeVectorsV1()
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name               string
		canonical, longest int
		guarantor          bool
	}{
		{"guarantor-ceiling-exact", MaxCanonicalObjectBytes, MaxCanonicalObjectBytes - 14, true},
		{"guarantor-ceiling-plus-one", MaxCanonicalObjectBytes + 1, MaxCanonicalObjectBytes - 13, false},
		{"worst-case-nested-request-string", 1_165_384, 1_165_360, true},
	}
	if len(vectors) != len(want) {
		t.Fatalf("got %d size vectors", len(vectors))
	}
	for index, vector := range vectors {
		expected := want[index]
		if vector.Name != expected.name || vector.CanonicalBytes != expected.canonical ||
			vector.LongestStringBytes != expected.longest || vector.AcceptedByGuarantor != expected.guarantor ||
			vector.AcceptedByDefault {
			t.Fatalf("size vector %d is %+v, want %+v", index, vector, expected)
		}
		value, _, err := BuildSizeVectorValueV1(vector.Construction)
		if err != nil {
			t.Fatal(err)
		}
		encoded, encodeErr := Canonical(value)
		if (encodeErr == nil) != expected.guarantor {
			t.Fatalf("%s: Guarantor encode error %v", vector.Name, encodeErr)
		}
		if encodeErr == nil {
			if err := Unmarshal(encoded, new(map[string]any)); err != nil {
				t.Fatalf("%s: Guarantor decode refused: %v", vector.Name, err)
			}
			if err := codec.Unmarshal(encoded, new(map[string]any)); err == nil {
				t.Fatalf("%s: the default codec decoded it", vector.Name)
			}
		}
	}
}
