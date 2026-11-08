package agentcommerce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

var custodyCellDigestPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)

var custodyNoStateInit = "sha256:" + strings.Repeat("0", 64)

// CustodyEffectAuthorization is the generic successor to the direct-payment
// authorization. It lets an owner authority admit an exact contract effect
// without granting custody permission to interpret chat, Intent, Agreement or
// model output. BodyHash and StateInitHashOrZero commit the exact TVM cells.
type CustodyEffectAuthorization struct {
	SchemaVersion        uint16                `json:"schema_version"`
	AuthorityID          string                `json:"authority_id"`
	OwnerID              string                `json:"owner_id"`
	AgentID              string                `json:"agent_id"`
	SourceAccount        string                `json:"source_account"`
	NetworkID            string                `json:"network_id"`
	NetworkGlobalID      int32                 `json:"network_global_id"`
	NetworkDomain        *CustodyNetworkDomain `json:"network_domain,omitempty"`
	ActionKind           string                `json:"action_kind"`
	StableActionID       string                `json:"stable_action_id"`
	ExactRequestDigest   string                `json:"exact_request_digest"`
	WriterGeneration     uint64                `json:"writer_generation"`
	WriterFenceDigest    string                `json:"writer_fence_digest"`
	PolicyRevision       uint64                `json:"policy_revision"`
	MandateDigest        string                `json:"mandate_digest"`
	ApprovalDigestOrZero string                `json:"approval_digest_or_zero"`
	AgreementBodyDigest  string                `json:"agreement_body_digest"`
	ObligationID         string                `json:"obligation_id"`
	Destination          string                `json:"destination"`
	AmountNanoTOS        uint64                `json:"amount_nanotos"`
	BodyHash             string                `json:"body_hash"`
	StateInitHashOrZero  string                `json:"state_init_hash_or_zero"`
	ExpiresAtUnix        uint64                `json:"expires_at_unix"`
	KeyID                string                `json:"key_id"`
	Proof                string                `json:"proof"`
}

// SignCustodyEffectAuthorization signs the effect authorization with the
// custody authorization controller that key custody holds under `controller`
// and fills its key ID and proof.
func SignCustodyEffectAuthorization(ctx context.Context, body CustodyEffectAuthorization, signer mldsa44.Signer,
	controller string) (CustodyEffectAuthorization, error) {
	body.KeyID, body.Proof = "", ""
	preimage, err := custodyEffectPreimage(body)
	if err != nil {
		return CustodyEffectAuthorization{}, err
	}
	keyID, proof, err := signCustodyDigest(ctx, signer, controller, sha256.Sum256(preimage))
	if err != nil {
		return CustodyEffectAuthorization{}, err
	}
	body.KeyID, body.Proof = keyID, proof
	return body, nil
}

func VerifyCustodyEffectAuthorization(value CustodyEffectAuthorization, resolver CustodyAuthorityResolver, now time.Time) error {
	if resolver == nil || now.Unix() < 0 || uint64(now.Unix()) >= value.ExpiresAtUnix {
		return errors.New("custody effect authorization is expired or has no authority resolver")
	}
	body := value
	body.KeyID, body.Proof = "", ""
	preimage, err := custodyEffectPreimage(body)
	if err != nil {
		return err
	}
	if err := verifyCustodyDigest(resolver, value.AuthorityID, value.OwnerID, value.AgentID, value.KeyID, value.Proof,
		sha256.Sum256(preimage), now); err != nil {
		return fmt.Errorf("custody effect authorization proof is invalid: %w", err)
	}
	return nil
}

// VerifyRelayCustodyEffectAuthorization rejects legacy V1 at every production
// relay effect boundary. V2 binds the exact genesis and target workchain.
func VerifyRelayCustodyEffectAuthorization(value CustodyEffectAuthorization,
	resolver CustodyAuthorityResolver, now time.Time) error {
	if value.SchemaVersion != 2 || value.NetworkDomain == nil {
		return errors.New("relay custody effect authorization requires schema v2 and a full network domain")
	}
	return VerifyCustodyEffectAuthorization(value, resolver, now)
}

func CustodyEffectAuthorizationPreimage(value CustodyEffectAuthorization) ([]byte, error) {
	value.KeyID, value.Proof = "", ""
	return custodyEffectPreimage(value)
}

func custodyEffectPreimage(body CustodyEffectAuthorization) ([]byte, error) {
	if (body.SchemaVersion != 1 && body.SchemaVersion != 2) || !boundedIdentifier(body.AuthorityID, 256) || !boundedIdentifier(body.OwnerID, 256) ||
		!boundedIdentifier(body.AgentID, 256) || !boundedIdentifier(body.SourceAccount, 256) || !boundedIdentifier(body.NetworkID, 128) ||
		validateCustodyAuthorizationNetwork(body.SchemaVersion, body.NetworkID, body.NetworkGlobalID, body.NetworkDomain) != nil ||
		!canonicalLowerToken(body.ActionKind) || !canonicalDigestPattern.MatchString(body.StableActionID) ||
		!canonicalDigestPattern.MatchString(body.ExactRequestDigest) || body.WriterGeneration == 0 ||
		!canonicalDigestPattern.MatchString(body.WriterFenceDigest) || body.PolicyRevision == 0 ||
		!canonicalDigestPattern.MatchString(body.MandateDigest) || !canonicalDigestOrZero(body.ApprovalDigestOrZero) ||
		!canonicalDigestPattern.MatchString(body.AgreementBodyDigest) || !boundedIdentifier(body.ObligationID, 256) ||
		!boundedIdentifier(body.Destination, 256) || body.AmountNanoTOS == 0 || !custodyCellDigestPattern.MatchString(body.BodyHash) ||
		!(custodyCellDigestPattern.MatchString(body.StateInitHashOrZero) || body.StateInitHashOrZero == custodyNoStateInit) || body.ExpiresAtUnix == 0 {
		return nil, errors.New("custody effect authorization body is invalid")
	}
	var output bytes.Buffer
	output.WriteString("TOS-CEA\x00")
	_ = binary.Write(&output, binary.BigEndian, body.SchemaVersion)
	for _, value := range []string{body.AuthorityID, body.OwnerID, body.AgentID, body.SourceAccount, body.NetworkID} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.NetworkGlobalID)
	if body.SchemaVersion == 2 {
		writeCustodyNetworkDomain(&output, *body.NetworkDomain)
	}
	for _, value := range []string{body.ActionKind, body.StableActionID, body.ExactRequestDigest} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.WriterGeneration)
	writeLP32String(&output, body.WriterFenceDigest)
	_ = binary.Write(&output, binary.BigEndian, body.PolicyRevision)
	for _, value := range []string{body.MandateDigest, body.ApprovalDigestOrZero, body.AgreementBodyDigest,
		body.ObligationID, body.Destination} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.AmountNanoTOS)
	for _, value := range []string{body.BodyHash, body.StateInitHashOrZero} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.ExpiresAtUnix)
	return output.Bytes(), nil
}
