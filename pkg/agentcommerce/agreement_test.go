package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type agreementKeyResolver map[string]ed25519.PublicKey

func (r agreementKeyResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	allowed := r[agentID]
	if allowed == nil || !allowed.Equal(key) {
		return errors.New("key is not authorized")
	}
	return nil
}

func validAgreementBody(t *testing.T, now time.Time) AgentAgreementBody {
	t.Helper()
	profileDigest := AgentSignatureProfileDigest()
	provider := "agent:" + strings.Repeat("a", 64)
	buyer := "agent:" + strings.Repeat("b", 64)
	body := AgentAgreementBody{
		SchemaVersion:  1,
		AgreementID:    "agreement:" + strings.Repeat("c", 64),
		Version:        1,
		NetworkContext: "tos:testnet",
		Participants: []AgreementParticipant{
			{AgentID: provider, Roles: []string{"provider"}},
			{AgentID: buyer, Roles: []string{"buyer"}},
		},
		ReferencedIntents: []string{"sha256:" + strings.Repeat("d", 64)},
		TermsContentType:  "text/plain",
		Terms:             []byte("Review the submitted source and deliver one report for 50 atomic units."),
		Obligations: []AgreementObligation{
			{ObligationID: "deliverable:report", Kind: "deliverable", ObligorAgentID: provider, BeneficiaryAgentID: buyer,
				SubjectContentType: "text/plain", Subject: []byte("bounded security report"), ConfidentialityPolicy: "private-to-participants",
				CancellationPolicy: "mutual-before-start", DisputePolicy: "manual-v1", AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "payment:final", Kind: "payment", ObligorAgentID: buyer, BeneficiaryAgentID: provider,
				DependsOnObligationIDs: []string{"deliverable:report"}, SubjectContentType: "text/plain", Subject: []byte("payment after accepted delivery"),
				Amount:                &AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "due-after-acceptance", DisputePolicy: "manual-v1",
				SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("network=tos:testnet"),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
		},
		AuthorizationPredicates: []AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: buyer},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment:final"}, EvidenceProfileURI: EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: provider},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"deliverable:report"}, EvidenceProfileURI: EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		},
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
	}
	prepared, err := PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestAgreementTargetsAndDigestBindEveryObligation(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	if err := ValidateAgreementBody(body); err != nil {
		t.Fatal(err)
	}
	first, err := AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	mutated := body
	mutated.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	mutated.Obligations[1].Amount = &AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "51", Unit: "total"}
	if err := ValidateAgreementBody(mutated); err == nil {
		t.Fatal("authority targets did not detect a changed amount")
	}
	mutated.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), mutated.AuthorizationPredicates...)
	for index := range mutated.AuthorizationPredicates {
		mutated.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	mutated, err = PrepareAgreementTargets(mutated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AgreementBodyDigest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changed obligation preserved Agreement digest")
	}
}

// An Agreement may name an external evidence profile, but not a retired
// built-in one: that URI would otherwise pass as an external profile nothing
// constrains.
func TestAgreementRefusesARetiredEvidenceProfile(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	withProfile := func(uri string) (AgentAgreementBody, error) {
		body := validAgreementBody(t, now)
		body.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), body.AuthorizationPredicates...)
		for index := range body.AuthorizationPredicates {
			body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		body.AuthorizationPredicates[0].EvidenceProfileURI = uri
		body.AuthorizationPredicates[0].EvidenceProfileDigest = "sha256:" + strings.Repeat("e", 64)
		body.AuthorizationPredicates[0].AuthoritySubject = AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet",
			SubjectIdentifier: "wallet:buyer", RepresentedAgentID: body.Participants[1].AgentID}
		prepared, err := PrepareAgreementTargets(body)
		if err != nil {
			return body, err
		}
		return prepared, ValidateAgreementBody(prepared)
	}
	if _, err := withProfile("tos.agreement.evidence.external-review.v1"); err != nil {
		t.Fatalf("an external evidence profile was refused: %v", err)
	}
	if _, err := withProfile("tos.agreement.evidence.paid-demand-quote.v1"); err == nil {
		t.Fatal("an Agreement naming the retired paid-demand evidence profile was accepted")
	}
}

func TestAgreementSuccessorRequiresExactConsecutiveLineage(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	predecessor := validAgreementBody(t, now)
	predecessorDigest, err := AgreementBodyDigest(predecessor)
	if err != nil {
		t.Fatal(err)
	}
	successor := predecessor
	successor.Version = 2
	successor.PredecessorAgreementDigest = predecessorDigest
	successor.Terms = []byte("Review the submitted source and deliver a narrower report for 45 atomic units.")
	successor.Obligations = append([]AgreementObligation(nil), predecessor.Obligations...)
	successor.Obligations[1].Amount = &AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "45", Unit: "total"}
	successor.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), predecessor.AuthorizationPredicates...)
	for index := range successor.AuthorizationPredicates {
		successor.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	successor, err = PrepareAgreementTargets(successor)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgreementSuccessor(predecessor, successor); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*AgentAgreementBody){
		"Agreement ID":      func(body *AgentAgreementBody) { body.AgreementID = "agreement:other" },
		"skipped version":   func(body *AgentAgreementBody) { body.Version = 3 },
		"wrong predecessor": func(body *AgentAgreementBody) { body.PredecessorAgreementDigest = "sha256:" + strings.Repeat("e", 64) },
		"different network": func(body *AgentAgreementBody) { body.NetworkContext = "tos:other" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := successor
			mutate(&mutated)
			mutated.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), mutated.AuthorizationPredicates...)
			for index := range mutated.AuthorizationPredicates {
				mutated.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
			}
			mutated, err = PrepareAgreementTargets(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateAgreementSuccessor(predecessor, mutated); err == nil {
				t.Fatalf("successor with %s was accepted", name)
			}
		})
	}
}

func TestAgreementRequiresAcyclicObligorAuthorizedGraph(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	broken := body
	broken.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	broken.Obligations[0].DependsOnObligationIDs = []string{"payment:final"}
	for index := range broken.AuthorizationPredicates {
		broken.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	if _, err := PrepareAgreementTargets(broken); err == nil {
		t.Fatal("cyclic obligation graph was accepted")
	}
	broken = body
	broken.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	broken.Obligations[0].AuthorizationPredicateIDs = []string{"predicate:buyer"}
	for index := range broken.AuthorizationPredicates {
		broken.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	if _, err := PrepareAgreementTargets(broken); err == nil {
		t.Fatal("obligation without obligor authority was accepted")
	}
}

func TestCompleteAgentEvidenceAuthorizesAgreement(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	digest, err := AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	keys := agreementKeyResolver{}
	agreement := AgentAgreement{Body: body}
	for _, predicate := range body.AuthorizationPredicates {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[predicate.AuthoritySubject.SubjectIdentifier] = publicKey
		acceptance, err := SignAgreementAcceptance(AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeSignedAgreementAcceptance(acceptance)
		if err != nil {
			t.Fatal(err)
		}
		agreement.AuthorizationEvidence = append(agreement.AuthorizationEvidence, AgreementAuthorizationEvidence{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
			AuthoritySubject: predicate.AuthoritySubject, PredicateIDs: []string{predicate.PredicateID},
			EvidenceProfileURI: predicate.EvidenceProfileURI, EvidenceProfileVersion: predicate.EvidenceProfileVersion,
			EvidenceProfileDigest: predicate.EvidenceProfileDigest, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			EvidenceContentType: AgreementAcceptanceContentType, Evidence: encoded,
		})
	}
	if err := ValidateAgreementAuthorization(agreement, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err != nil {
		t.Fatal(err)
	}
	missing := agreement
	missing.AuthorizationEvidence = missing.AuthorizationEvidence[:1]
	if err := ValidateAgreementAuthorization(missing, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err == nil {
		t.Fatal("partially authorized Agreement was accepted")
	}
	replayed := agreement
	replayed.Body.Terms = []byte("different terms")
	for index := range replayed.Body.AuthorizationPredicates {
		replayed.Body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	replayed.Body, err = PrepareAgreementTargets(replayed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgreementAuthorization(replayed, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err == nil {
		t.Fatal("evidence replayed onto another Agreement body")
	}
}

func TestAgreementAuthorizationEnforcesBodyPredicateAndAcceptanceValidity(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()

	t.Run("body bounds", func(t *testing.T) {
		body := validAgreementBody(t, now)
		agreement, verifier := fullyAuthorizedAgentAgreement(t, body, body.ExpiresAtUnix)
		if err := ValidateAgreementAuthorization(agreement, verifier, now.Add(-time.Second)); err == nil {
			t.Fatal("Agreement authorized before its valid-from time")
		}
		if err := ValidateAgreementAuthorization(agreement, verifier, time.Unix(int64(body.ExpiresAtUnix), 0)); err == nil {
			t.Fatal("Agreement authorized at its exclusive expiry")
		}
	})

	t.Run("predicate not yet valid", func(t *testing.T) {
		body := validAgreementBody(t, now)
		for index := range body.AuthorizationPredicates {
			body.AuthorizationPredicates[index].ValidFromUnix = uint64(now.Add(time.Minute).Unix())
			body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		var err error
		body, err = PrepareAgreementTargets(body)
		if err != nil {
			t.Fatal(err)
		}
		agreement, verifier := fullyAuthorizedAgentAgreement(t, body, body.ExpiresAtUnix)
		if err := ValidateAgreementAuthorization(agreement, verifier, now); err == nil {
			t.Fatal("Agreement authorized before its predicates became valid")
		}
	})

	t.Run("acceptance outlives body or predicate", func(t *testing.T) {
		body := validAgreementBody(t, now)
		agreement, verifier := fullyAuthorizedAgentAgreement(t, body, uint64(now.Add(2*time.Hour).Unix()))
		if err := ValidateAgreementAuthorization(agreement, verifier, now); err == nil {
			t.Fatal("acceptance extending beyond the Agreement validity window was accepted")
		}

		body = validAgreementBody(t, now)
		body.ExpiresAtUnix = uint64(now.Add(2 * time.Hour).Unix())
		for index := range body.AuthorizationPredicates {
			body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		body, err := PrepareAgreementTargets(body)
		if err != nil {
			t.Fatal(err)
		}
		agreement, verifier = fullyAuthorizedAgentAgreement(t, body, uint64(now.Add(90*time.Minute).Unix()))
		if err := ValidateAgreementAuthorization(agreement, verifier, now); err == nil {
			t.Fatal("acceptance extending beyond its predicate validity window was accepted")
		}
	})
}

func fullyAuthorizedAgentAgreement(t *testing.T, body AgentAgreementBody,
	acceptanceExpiresAtUnix uint64) (AgentAgreement, AgentSignatureEvidenceVerifier) {
	t.Helper()
	digest, err := AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	keys := agreementKeyResolver{}
	agreement := AgentAgreement{Body: body}
	for _, predicate := range body.AuthorizationPredicates {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[predicate.AuthoritySubject.SubjectIdentifier] = publicKey
		acceptance, err := SignAgreementAcceptance(AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: acceptanceExpiresAtUnix,
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := AgentSignatureEvidence(body, acceptance)
		if err != nil {
			t.Fatal(err)
		}
		agreement.AuthorizationEvidence = append(agreement.AuthorizationEvidence, evidence)
	}
	return agreement, AgentSignatureEvidenceVerifier{Resolver: keys}
}
