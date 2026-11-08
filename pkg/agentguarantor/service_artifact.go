package agentguarantor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	ServiceProfileArtifactDomain   = "tos.service.agent-guarantor-service-profile-artifact.v1"
	ServiceProfileContentType      = "application/vnd.tos.service.agent-guarantor-service-profile.v1+cbor"
	ServiceIntentPayloadProfileURI = "tos.service.agent-intent-payload.v1"
	ServiceIntentOpcodeNamespace   = "PUBLICATION"
	ServiceIntentOpcodeName        = "POST"
	ServiceProfileArtifactSchemaV1 = 1
)

type GuarantorServiceProfileRevisionArtifactV1 struct {
	SchemaVersion                uint16                                 `json:"schema_version"`
	ServiceIntentOperationDigest string                                 `json:"service_intent_operation_digest"`
	ServiceIntentOperation       agentcommerce.AgentOperationEnvelopeV1 `json:"service_intent_operation"`
	IntentPayload                agentcommerce.AgentIntentPayload       `json:"intent_payload"`
	ServiceProfile               ServiceProfileV1                       `json:"service_profile"`
}

type GuarantorServiceProfileArtifactV1 struct {
	SchemaVersion                        uint16                                      `json:"schema_version"`
	SelectedServiceIntentOperationDigest string                                      `json:"selected_service_intent_operation_digest"`
	SelectedServiceProfileDigest         string                                      `json:"selected_service_profile_digest"`
	Revisions                            []GuarantorServiceProfileRevisionArtifactV1 `json:"revisions"`
}

func ServiceProfileArtifactDigestV1(artifact GuarantorServiceProfileArtifactV1) (string, error) {
	if err := validateServiceProfileArtifactShapeV1(artifact); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ServiceProfileArtifactDomain, artifact)
}

func VerifyServiceProfileArtifactV1(artifact GuarantorServiceProfileArtifactV1,
	resolver agentcommerce.AgentOperationAuthorityResolver, now time.Time) error {
	if err := validateServiceProfileArtifactShapeV1(artifact); err != nil || resolver == nil {
		return errors.New("Guarantor service profile artifact is invalid")
	}
	var priorOperationDigest, priorProfileDigest, profileID, providerAgentID, authorityDomain string
	for index, revision := range artifact.Revisions {
		payloadBytes, err := guarantorCodec.Marshal(revision.IntentPayload)
		if err != nil || agentcommerce.VerifyAgentOperationV1(revision.ServiceIntentOperation, payloadBytes, resolver, now) != nil {
			return errors.New("Guarantor service profile publication operation does not verify")
		}
		operation := revision.ServiceIntentOperation.Body
		operationDigest, err := agentcommerce.AgentOperationEnvelopeDigestV1(revision.ServiceIntentOperation)
		if err != nil || operationDigest != revision.ServiceIntentOperationDigest ||
			operation.OpcodeNamespace != ServiceIntentOpcodeNamespace || operation.OpcodeName != ServiceIntentOpcodeName ||
			operation.OpcodeVersion != 1 || operation.PayloadProfile.ProfileURI != ServiceIntentPayloadProfileURI ||
			operation.PayloadProfile.ProfileVersion != 1 {
			return errors.New("Guarantor service profile publication identity is invalid")
		}
		profile := revision.ServiceProfile
		if err := ValidateServiceProfile(profile, now); err != nil || operation.ActorAgentID != profile.ProviderAgentID ||
			operation.ObjectID != profile.ProfileID || operation.Sequence != profile.Revision {
			return errors.New("Guarantor service profile differs from its publication")
		}
		profileBytes, err := guarantorCodec.Marshal(profile)
		profileDigest, digestErr := ServiceProfileDigest(profile)
		contentHash := sha256.Sum256(profileBytes)
		detail := revision.IntentPayload.DetailDescriptor
		if err != nil || digestErr != nil || detail.ContentType != ServiceProfileContentType ||
			detail.ContentDigest != "sha256:"+hex.EncodeToString(contentHash[:]) || detail.ContentSize != uint64(len(profileBytes)) ||
			len(detail.InlineContent) != 0 && string(detail.InlineContent) != string(profileBytes) {
			return errors.New("Guarantor service profile detail descriptor does not bind its canonical bytes")
		}
		if index == 0 {
			if profile.Revision != 1 || profile.PredecessorProfileDigest != "" || len(operation.PredecessorDigests) != 0 {
				return errors.New("Guarantor service profile lineage does not start at revision one")
			}
			profileID, providerAgentID, authorityDomain = profile.ProfileID, profile.ProviderAgentID, profile.AuthorityDomainDigest
		} else if profile.Revision != uint64(index+1) || profile.ProfileID != profileID ||
			profile.ProviderAgentID != providerAgentID || profile.AuthorityDomainDigest != authorityDomain ||
			profile.PredecessorProfileDigest != priorProfileDigest || len(operation.PredecessorDigests) != 1 ||
			operation.PredecessorDigests[0] != priorOperationDigest {
			return errors.New("Guarantor service profile lineage is not contiguous")
		}
		priorOperationDigest, priorProfileDigest = operationDigest, profileDigest
	}
	if artifact.SelectedServiceIntentOperationDigest != priorOperationDigest ||
		artifact.SelectedServiceProfileDigest != priorProfileDigest {
		return errors.New("Guarantor service profile selected head differs from its lineage")
	}
	return nil
}

// ResolveServiceProfileArtifactV1 verifies the complete immutable publication
// lineage and returns its selected profile. Callers must not accept a raw
// ServiceProfileV1 where an offer or other side effect depends on publication
// authority.
func ResolveServiceProfileArtifactV1(artifact GuarantorServiceProfileArtifactV1,
	resolver agentcommerce.AgentOperationAuthorityResolver, now time.Time) (ServiceProfileV1, error) {
	if err := VerifyServiceProfileArtifactV1(artifact, resolver, now); err != nil {
		return ServiceProfileV1{}, err
	}
	return artifact.Revisions[len(artifact.Revisions)-1].ServiceProfile, nil
}

func validateServiceProfileArtifactShapeV1(artifact GuarantorServiceProfileArtifactV1) error {
	if artifact.SchemaVersion != ServiceProfileArtifactSchemaV1 || len(artifact.Revisions) == 0 ||
		len(artifact.Revisions) > MaxProfileRevisions || !validDigest(artifact.SelectedServiceIntentOperationDigest) ||
		!validDigest(artifact.SelectedServiceProfileDigest) {
		return errors.New("Guarantor service profile artifact shape is invalid")
	}
	for _, revision := range artifact.Revisions {
		if revision.SchemaVersion != 1 || !validDigest(revision.ServiceIntentOperationDigest) ||
			agentcommerce.ValidateAgentIntentPayload(revision.IntentPayload) != nil {
			return errors.New("Guarantor service profile revision artifact shape is invalid")
		}
	}
	canonical, err := guarantorCodec.Marshal(artifact)
	if err != nil || len(canonical) > MaxProfileArtifactBytes {
		return errors.New("Guarantor service profile artifact exceeds its canonical bound")
	}
	return nil
}
