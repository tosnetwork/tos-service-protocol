package agentguarantor

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// prerequisiteStore resolves content-addressed prerequisites by digest and
// delegates authority checks to the signed control-resolution test resolver.
type prerequisiteStore struct {
	testControlResolver
	objects  map[string][]byte
	override []byte
}

func (store prerequisiteStore) ResolveImmutableGuarantorEvidence(descriptor ImmutableEvidenceDescriptorV1) ([]byte, error) {
	if store.override != nil {
		return append([]byte(nil), store.override...), nil
	}
	wire, found := store.objects[descriptor.ContentDigest]
	if !found {
		return nil, errors.New("not stored")
	}
	return append([]byte(nil), wire...), nil
}

type prerequisiteFixture struct {
	evidence AuthorizedCoverageActivationEvidenceV1
	terms    CoverageTermsV1
	store    prerequisiteStore
	now      time.Time
}

func prerequisiteItem(t *testing.T, contentType, policy string, value any, digest string) (CanonicalGuarantorEvidenceItemV1, []byte) {
	t.Helper()
	wire, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return CanonicalGuarantorEvidenceItemV1{ContentType: contentType, EvidenceProfileDigest: policy,
		EvidenceEnvelopeDigest: digest, Representation: "content_addressed",
		ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: contentType, ContentDigest: digest,
			ContentSize: uint64(len(wire)), RetrievalPolicyDigest: policy}}, wire
}

func sortEvidenceItems(t *testing.T, items []CanonicalGuarantorEvidenceItemV1) {
	t.Helper()
	sort.Slice(items, func(i, j int) bool {
		left, leftErr := Canonical(items[i])
		right, rightErr := Canonical(items[j])
		if leftErr != nil || rightErr != nil {
			t.Fatal("evidence item cannot be encoded")
		}
		return bytes.Compare(left, right) < 0
	})
}

func newPrerequisiteFixture(t *testing.T, independent bool) prerequisiteFixture {
	t.Helper()
	terms, independence, _, now := testOperationalIndependenceEvidence(t)
	agreementDigest := independence.Body.CoverageAgreementBodyDigest
	if !independent {
		terms.SelectedAssuranceLevel = AssuranceCollateralAttested
	}
	asset := testAsset()
	executionProfile := testRef("6", "independent-execution")
	terms.CoverageAsset = asset
	terms.SelectedCollateralProfileDigest = testDigest("7")
	terms.CollateralTerms = &CollateralTermsV1{SelectedCollateralProfileDigest: terms.SelectedCollateralProfileDigest,
		Amount: AtomicAmountV1{Asset: asset, AmountAtomic: "500"}, IndependentExecutionProfile: &executionProfile,
		IndependentExecutionAuthoritySubjects: []string{"authority:executor"}, IndependentExecutionQuorumRule: "all"}
	authorization := independence.Authorizations[0]
	collateral := AuthorizedCollateralEvidenceV1{Body: CollateralEvidenceBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CollateralObligationID: terms.CollateralObligationID,
		TransitionKind: "lock"},
		ResultingPositionState: CollateralPositionStateV1{SchemaVersion: 1, Status: CollateralLocked,
			RemainingAmount: AtomicAmountV1{Asset: asset, AmountAtomic: "500"}},
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{authorization}}
	collateral.CollateralTransitionActionBody.TransitionBinding.AuthorizationBinding = CollateralAuthorizationBindingV1{
		AuthorizationProfile: executionProfile, AuthorizationSubjects: []string{"authority:executor"},
		AuthorizationQuorumRule: "all"}
	collateralDigest, err := CollateralEvidenceDigestV1(collateral)
	if err != nil {
		t.Fatal(err)
	}
	control := AuthorizedCollateralControlEvidenceV1{Body: CollateralControlEvidenceBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CollateralObligationID: terms.CollateralObligationID},
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{authorization}}
	controlDigest, err := CollateralControlEvidenceDigestV1(control)
	if err != nil {
		t.Fatal(err)
	}
	store := prerequisiteStore{testControlResolver: testControlResolver{controller: "authority:independent",
		operationRouteSurvives: true}, objects: map[string][]byte{}}
	var items []CanonicalGuarantorEvidenceItemV1
	item, wire := prerequisiteItem(t, CollateralEvidenceContentTypeV1, terms.SelectedCollateralProfileDigest, collateral, collateralDigest)
	items, store.objects[collateralDigest] = append(items, item), wire
	item, wire = prerequisiteItem(t, CollateralControlEvidenceContentTypeV1, terms.SelectedCollateralProfileDigest, control, controlDigest)
	items, store.objects[controlDigest] = append(items, item), wire
	if independent {
		independenceDigest, err := OperationalIndependenceEvidenceDigestV1(independence)
		if err != nil {
			t.Fatal(err)
		}
		termsDigest, err := OperationalIndependenceTermsDigestV1(*terms.OperationalIndependenceTerms)
		if err != nil {
			t.Fatal(err)
		}
		item, wire = prerequisiteItem(t, OperationalIndependenceEvidenceContentTypeV1, termsDigest, independence, independenceDigest)
		items, store.objects[independenceDigest] = append(items, item), wire
	}
	sortEvidenceItems(t, items)
	set := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "coverage-activation-collateral",
		ContextDigest: agreementDigest, Items: items}
	var evidence AuthorizedCoverageActivationEvidenceV1
	evidence.Body.CoverageAgreementBodyDigest = agreementDigest
	evidence.PrerequisiteEvidenceSet = &set
	return prerequisiteFixture{evidence: evidence, terms: terms, store: store, now: now}
}

// stubSignedCollateralVerifiers replaces only the two signed-object verifiers
// for which no signed fixture exists; operational independence stays real.
func stubSignedCollateralVerifiers(t *testing.T) {
	t.Helper()
	saved := activationPrerequisiteVerifiersV1
	activationPrerequisiteVerifiersV1.collateral = func(AuthorizedCollateralEvidenceV1, CoverageTermsV1, AuthorityKeyResolver,
		agentcommerce.FenceAuthorityResolver, time.Time, CollateralAdapterFinalityVerifier, bool) error {
		return nil
	}
	activationPrerequisiteVerifiersV1.control = func(AuthorizedCollateralControlEvidenceV1, string, string, string,
		CollateralControlDisclosureV1, ProfileRefV1, []string, string, AuthorityKeyResolver, time.Time) error {
		return nil
	}
	t.Cleanup(func() { activationPrerequisiteVerifiersV1 = saved })
}

func (f prerequisiteFixture) verify(resolver AuthorityKeyResolver) error {
	return verifyActivationCollateralPrerequisiteV1(f.evidence, f.terms, resolver, nil, nil, f.now)
}

func TestActivationPrerequisiteVerifiersAreTheProductionVerifiers(t *testing.T) {
	pointer := func(value any) uintptr { return reflect.ValueOf(value).Pointer() }
	if pointer(activationPrerequisiteVerifiersV1.collateral) != pointer(VerifyCollateralEvidenceV1) ||
		pointer(activationPrerequisiteVerifiersV1.control) != pointer(VerifyCollateralControlEvidenceV1) ||
		pointer(activationPrerequisiteVerifiersV1.independence) != pointer(VerifyOperationalIndependenceEvidenceV1) {
		t.Fatal("activation prerequisite verifiers are not the production verifiers")
	}
}

func TestActivationPrerequisitesResolveDescriptorsCollateralAttested(t *testing.T) {
	stubSignedCollateralVerifiers(t)
	fixture := newPrerequisiteFixture(t, false)
	if err := fixture.verify(fixture.store); err != nil {
		t.Fatalf("descriptor-only collateral prerequisites were refused: %v", err)
	}
}

func TestActivationPrerequisitesResolveDescriptorsIndependentlyEnforced(t *testing.T) {
	stubSignedCollateralVerifiers(t)
	fixture := newPrerequisiteFixture(t, true)
	if err := fixture.verify(fixture.store); err != nil {
		t.Fatalf("descriptor-only independently enforced prerequisites were refused: %v", err)
	}
}

func TestActivationPrerequisitesRefuseUnboundDescriptors(t *testing.T) {
	stubSignedCollateralVerifiers(t)
	mutate := func(name string, change func(*CanonicalGuarantorEvidenceItemV1)) {
		t.Run(name, func(t *testing.T) {
			fixture := newPrerequisiteFixture(t, true)
			set := *fixture.evidence.PrerequisiteEvidenceSet
			set.Items = append([]CanonicalGuarantorEvidenceItemV1(nil), set.Items...)
			for index := range set.Items {
				if set.Items[index].ContentType == CollateralEvidenceContentTypeV1 {
					item := set.Items[index]
					descriptor := *item.ImmutableDescriptor
					item.ImmutableDescriptor = &descriptor
					change(&item)
					set.Items[index] = item
				}
			}
			sortEvidenceItems(t, set.Items)
			fixture.evidence.PrerequisiteEvidenceSet = &set
			if err := fixture.verify(fixture.store); err == nil {
				t.Fatal("an unbound prerequisite descriptor was accepted")
			}
		})
	}
	mutate("content type", func(item *CanonicalGuarantorEvidenceItemV1) {
		item.ImmutableDescriptor.ContentType = CollateralControlEvidenceContentTypeV1
	})
	mutate("digest", func(item *CanonicalGuarantorEvidenceItemV1) { item.ImmutableDescriptor.ContentDigest = testDigest("0") })
	mutate("size", func(item *CanonicalGuarantorEvidenceItemV1) { item.ImmutableDescriptor.ContentSize++ })
	mutate("retrieval policy", func(item *CanonicalGuarantorEvidenceItemV1) {
		item.ImmutableDescriptor.RetrievalPolicyDigest = testDigest("0")
	})
	mutate("policy and profile together", func(item *CanonicalGuarantorEvidenceItemV1) {
		item.ImmutableDescriptor.RetrievalPolicyDigest = testDigest("0")
		item.EvidenceProfileDigest = testDigest("0")
	})
	mutate("inline", func(item *CanonicalGuarantorEvidenceItemV1) {
		item.Representation = "inline"
		item.ImmutableDescriptor = nil
		item.CanonicalEnvelopeBytes = []byte{0xa0}
	})
}

func TestActivationPrerequisitesRequireResolverAndExactBytes(t *testing.T) {
	stubSignedCollateralVerifiers(t)
	fixture := newPrerequisiteFixture(t, false)
	if err := fixture.verify(testControlResolver{controller: "authority:independent", operationRouteSurvives: true}); err == nil {
		t.Fatal("prerequisites were accepted without an immutable evidence resolver")
	}
	substituted := fixture.store
	for _, wire := range fixture.store.objects {
		substituted.override = bytes.Repeat([]byte{0xa0}, len(wire))
		break
	}
	if err := fixture.verify(substituted); err == nil {
		t.Fatal("prerequisites were accepted from substituted resolved bytes")
	}
}
