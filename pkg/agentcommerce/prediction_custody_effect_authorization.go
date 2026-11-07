package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tosnetwork/tosutils-go/address"
)

const (
	PredictionCustodyEffectProfileV1 = "tos.prediction.checked-call.v1"
	AgentCheckedContractCallV2Opcode = uint32(0x41475007)
	maximumPredictionCustodyJSON     = 16 << 10
	maximumAgentSignedActionValue    = uint64(1<<48 - 1)
)

var predictionCustodyEffectKinds = map[string]struct{}{
	"prediction.collateral.deposit":        {},
	"prediction.reserve.top-up":            {},
	"prediction.trading-key.rotate":        {},
	"prediction.order.cancel-exact":        {},
	"prediction.order.nonce-floor.raise":   {},
	"prediction.match.submit":              {},
	"prediction.position.split":            {},
	"prediction.position.merge":            {},
	"prediction.position.claim":            {},
	"prediction.collateral.withdraw":       {},
	"prediction.resolution.report":         {},
	"prediction.resolution.challenge":      {},
	"prediction.resolution.finalize":       {},
	"prediction.challenge-bond.withdraw":   {},
	"prediction.market.advance-phase":      {},
	"prediction.market.compact":            {},
	"prediction.terminal-surplus.withdraw": {},
}

// PredictionCustodyEffectAuthorizationV1 is an owner-custody capability for
// one exact PredictionMarket call through the Agent Account checked-call v2
// action. It is deliberately not a variant of the Agreement custody effect
// authorization: no Agreement field can be invented to make a prediction
// action fit that schema.
type PredictionCustodyEffectAuthorizationV1 struct {
	SchemaVersion              uint16               `json:"schema_version"`
	Profile                    string               `json:"profile"`
	AuthorityID                string               `json:"authority_id"`
	OwnerID                    string               `json:"owner_id"`
	AgentID                    string               `json:"agent_id"`
	SourceAccount              string               `json:"source_account"`
	SourceAgentAccountCodeHash string               `json:"source_agent_account_code_hash"`
	NetworkDomain              CustodyNetworkDomain `json:"network_domain"`
	ActionKind                 string               `json:"action_kind"`
	EffectKind                 string               `json:"effect_kind"`
	StableActionID             string               `json:"stable_action_id"`
	ExactRequestDigest         string               `json:"exact_request_digest"`
	WriterGeneration           uint64               `json:"writer_generation"`
	WriterFenceDigest          string               `json:"writer_fence_digest"`
	PolicyRevision             uint64               `json:"policy_revision"`
	MandateDigest              string               `json:"mandate_digest"`
	ApprovalDigestOrZero       string               `json:"approval_digest_or_zero"`
	MarketID                   string               `json:"market_id"`
	MarketAddress              string               `json:"market_address"`
	// Destination duplicates MarketAddress at the transport boundary.  It is
	// required so the JSON accepted by tosctl is explicit about the target;
	// validation below makes the duplicate non-malleable.
	Destination      string `json:"destination"`
	MarketConfigHash string `json:"market_config_hash"`
	MarketCodeHash   string `json:"market_code_hash"`
	AmountNanoTOS    uint64 `json:"amount_nanotos"`
	BodyHash         string `json:"body_hash"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
	PublicKey        string `json:"public_key"`
	Proof            string `json:"proof"`
}

func IsPredictionCustodyEffectKind(kind string) bool {
	_, ok := predictionCustodyEffectKinds[kind]
	return ok
}

func SignPredictionCustodyEffectAuthorizationV1(
	body PredictionCustodyEffectAuthorizationV1,
	privateKey ed25519.PrivateKey,
) (PredictionCustodyEffectAuthorizationV1, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return PredictionCustodyEffectAuthorizationV1{}, errors.New("prediction custody signing key is invalid")
	}
	body.PublicKey, body.Proof = "", ""
	preimage, err := predictionCustodyEffectPreimageV1(body)
	if err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, err
	}
	digest := sha256.Sum256(preimage)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	body.PublicKey = "ed25519:" + hex.EncodeToString(publicKey)
	body.Proof = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return body, nil
}

func VerifyPredictionCustodyEffectAuthorizationV1(
	value PredictionCustodyEffectAuthorizationV1,
	resolver CustodyAuthorityResolver,
	now time.Time,
) error {
	if resolver == nil || now.Unix() < 0 || uint64(now.Unix()) >= value.ExpiresAtUnix {
		return errors.New("prediction custody effect is expired or has no authority resolver")
	}
	publicKey, err := parseEd25519PublicKey(value.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeCustodyKey(value.AuthorityID, value.OwnerID, value.AgentID, publicKey, now); err != nil {
		return err
	}
	proof, err := parseHexEd25519Signature(value.Proof)
	if err != nil {
		return err
	}
	body := value
	body.PublicKey, body.Proof = "", ""
	preimage, err := predictionCustodyEffectPreimageV1(body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(preimage)
	if !ed25519.Verify(publicKey, digest[:], proof) {
		return errors.New("prediction custody effect proof is invalid")
	}
	return nil
}

func PredictionCustodyEffectAuthorizationPreimageV1(
	value PredictionCustodyEffectAuthorizationV1,
) ([]byte, error) {
	value.PublicKey, value.Proof = "", ""
	return predictionCustodyEffectPreimageV1(value)
}

func DecodePredictionCustodyEffectAuthorizationV1JSON(
	raw []byte,
) (PredictionCustodyEffectAuthorizationV1, error) {
	if len(raw) == 0 || len(raw) > maximumPredictionCustodyJSON {
		return PredictionCustodyEffectAuthorizationV1{}, errors.New("prediction custody JSON exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value PredictionCustodyEffectAuthorizationV1
	if err := decoder.Decode(&value); err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, fmt.Errorf("decode prediction custody effect: %w", err)
	}
	if err := requirePredictionCustodyJSONEOF(decoder); err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, err
	}
	if _, err := predictionCustodyEffectPreimageV1(value); err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, err
	}
	if _, err := parseEd25519PublicKey(value.PublicKey); err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, err
	}
	if _, err := parseHexEd25519Signature(value.Proof); err != nil {
		return PredictionCustodyEffectAuthorizationV1{}, err
	}
	return value, nil
}

func predictionCustodyEffectPreimageV1(body PredictionCustodyEffectAuthorizationV1) ([]byte, error) {
	source, sourceErr := parsePredictionCustodyAddress(body.SourceAccount)
	market, marketErr := parsePredictionCustodyAddress(body.MarketAddress)
	if body.SchemaVersion != 1 || body.Profile != PredictionCustodyEffectProfileV1 ||
		!boundedIdentifier(body.AuthorityID, 256) || !boundedIdentifier(body.OwnerID, 256) ||
		!boundedIdentifier(body.AgentID, 256) || sourceErr != nil || marketErr != nil ||
		source.Workchain() != body.NetworkDomain.WorkchainID || market.Workchain() != body.NetworkDomain.WorkchainID ||
		body.SourceAccount == body.MarketAddress || ValidateCustodyNetworkDomain(body.NetworkDomain) != nil ||
		!IsPredictionCustodyEffectKind(body.ActionKind) || body.EffectKind != body.ActionKind ||
		!canonicalDigestPattern.MatchString(body.StableActionID) ||
		!canonicalDigestPattern.MatchString(body.ExactRequestDigest) || body.WriterGeneration == 0 ||
		!canonicalDigestPattern.MatchString(body.WriterFenceDigest) || body.PolicyRevision == 0 ||
		!canonicalDigestPattern.MatchString(body.MandateDigest) || !canonicalDigestOrZero(body.ApprovalDigestOrZero) ||
		!canonicalNonZeroDigest(body.MarketID, canonicalDigestPattern) ||
		body.Destination != body.MarketAddress ||
		!canonicalNonZeroDigest(body.SourceAgentAccountCodeHash, custodyCellDigestPattern) ||
		!canonicalNonZeroDigest(body.MarketConfigHash, custodyCellDigestPattern) ||
		!canonicalNonZeroDigest(body.MarketCodeHash, custodyCellDigestPattern) ||
		body.AmountNanoTOS == 0 || body.AmountNanoTOS > maximumAgentSignedActionValue ||
		!custodyCellDigestPattern.MatchString(body.BodyHash) || body.ExpiresAtUnix == 0 {
		return nil, errors.New("prediction custody effect authorization body is invalid")
	}

	var output bytes.Buffer
	output.WriteString("TOS-PCEA\x00")
	_ = binary.Write(&output, binary.BigEndian, body.SchemaVersion)
	for _, value := range []string{
		body.Profile,
		body.AuthorityID,
		body.OwnerID,
		body.AgentID,
		body.SourceAccount,
		body.SourceAgentAccountCodeHash,
	} {
		writeLP32String(&output, value)
	}
	writeCustodyNetworkDomain(&output, body.NetworkDomain)
	for _, value := range []string{
		body.ActionKind,
		body.EffectKind,
		body.StableActionID,
		body.ExactRequestDigest,
	} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.WriterGeneration)
	writeLP32String(&output, body.WriterFenceDigest)
	_ = binary.Write(&output, binary.BigEndian, body.PolicyRevision)
	for _, value := range []string{
		body.MandateDigest,
		body.ApprovalDigestOrZero,
		body.MarketID,
		body.MarketAddress,
		body.MarketConfigHash,
		body.MarketCodeHash,
	} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.AmountNanoTOS)
	writeLP32String(&output, body.BodyHash)
	_ = binary.Write(&output, binary.BigEndian, body.ExpiresAtUnix)
	return output.Bytes(), nil
}

func parsePredictionCustodyAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 ||
		parsed.StringRaw() != value || parsed.Workchain() != -1 && parsed.Workchain() != 0 {
		return nil, errors.New("prediction custody address is not canonical")
	}
	return parsed, nil
}

func canonicalNonZeroDigest(value string, pattern interface{ MatchString(string) bool }) bool {
	if !pattern.MatchString(value) {
		return false
	}
	separator := strings.IndexByte(value, ':')
	return separator >= 0 && strings.Trim(value[separator+1:], "0") != ""
}

func requirePredictionCustodyJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("prediction custody JSON contains multiple values")
		}
		return fmt.Errorf("decode prediction custody JSON tail: %w", err)
	}
	return nil
}
