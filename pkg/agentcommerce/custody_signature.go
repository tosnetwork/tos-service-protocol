package agentcommerce

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// ErrEd25519CustodyAuthorization reports an Ed25519 custody authorization key
// or proof. The custody authorization key is Pure ML-DSA-44 under
// TOS-CUSTODY-AUTHORIZATION-V1 only; there is no other suite to select.
var ErrEd25519CustodyAuthorization = errors.New(
	"Ed25519 custody authorization keys and proofs are not accepted; the custody authorization key is ML-DSA-44")

// CustodyAuthorityResolver pins the custody authorization key independently
// of the proof. ResolveCustodyAuthorizationKey returns the 1,312-byte public
// key named by keyID only when that key is the owner-pinned custody
// authorization key for the exact authority, owner and Agent at `at`; any
// unknown, revoked, ambiguous or unavailable state is an error. Verify is the
// ML-DSA-44 verification boundary (normally the pinned tosctl helper).
// Callers always recompute the key ID of the returned key, so a key carried by
// the proof can never become its own authority.
type CustodyAuthorityResolver interface {
	mldsa44.Verifier
	ResolveCustodyAuthorizationKey(authorityID, ownerID, agentID string, keyID [mldsa44.KeyIDSize]byte,
		at time.Time) ([]byte, error)
}

// ParseCustodyAuthorizationKeyID reads the only text form of a custody
// authorization key reference, mldsa44:<64 lowercase hex>.
func ParseCustodyAuthorizationKeyID(value string) ([mldsa44.KeyIDSize]byte, error) {
	if strings.HasPrefix(value, removedActionAuthorityPrefix) {
		return [mldsa44.KeyIDSize]byte{}, ErrEd25519CustodyAuthorization
	}
	keyID, err := mldsa44.ParseKeyIDText(value)
	if err != nil {
		return [mldsa44.KeyIDSize]byte{}, errors.New("custody authorization key ID is not canonical mldsa44:<64 lowercase hex>")
	}
	return keyID, nil
}

// ParseCustodyAuthorizationSignature reads the only text form of a custody
// authorization proof, mldsa44:<canonical unpadded URL-safe Base64 of 2,420
// bytes>.
func ParseCustodyAuthorizationSignature(value string) ([]byte, error) {
	if strings.HasPrefix(value, removedActionAuthorityPrefix) {
		return nil, ErrEd25519CustodyAuthorization
	}
	signature, err := mldsa44.ParseSignatureText(value)
	if err != nil {
		return nil, errors.New("custody authorization proof is not canonical mldsa44:<Base64url of 2,420 bytes>")
	}
	return signature, nil
}

// signCustodyDigest asks key custody to sign one 32-byte preimage digest with
// a named controller under the custody authorization context and returns the
// key ID and proof in their text forms, checked for shape and for a key ID
// that matches the returned key.
func signCustodyDigest(ctx context.Context, signer mldsa44.Signer, controller string,
	digest [32]byte) (string, string, error) {
	if ctx == nil || signer == nil || controller == "" {
		return "", "", errors.New("custody authorization signing request is invalid")
	}
	signed, err := signer.Sign(ctx, controller, mldsa44.UseCustodyAuthorization, digest[:])
	if err != nil {
		return "", "", fmt.Errorf("custody authorization signing failed: %w", err)
	}
	if err := mldsa44.CheckSignature(signed); err != nil {
		return "", "", errors.New("custody authorization signer returned a malformed signature")
	}
	proof, err := mldsa44.SignatureText(signed.Signature)
	if err != nil {
		return "", "", errors.New("custody authorization signer returned a malformed signature")
	}
	return mldsa44.KeyIDText(signed.KeyID), proof, nil
}

// verifyCustodyDigest resolves the pinned custody authorization key named by
// keyIDText for the exact authority, owner and Agent, requires it to derive
// that key ID, and verifies the Pure ML-DSA-44 proof over the 32-byte preimage
// digest under the custody authorization context.
func verifyCustodyDigest(resolver CustodyAuthorityResolver, authorityID, ownerID, agentID, keyIDText,
	proofText string, digest [32]byte, at time.Time) error {
	if resolver == nil {
		return errors.New("custody authorization resolver is unavailable")
	}
	keyID, err := ParseCustodyAuthorizationKeyID(keyIDText)
	if err != nil {
		return err
	}
	proof, err := ParseCustodyAuthorizationSignature(proofText)
	if err != nil {
		return err
	}
	publicKey, err := resolver.ResolveCustodyAuthorizationKey(authorityID, ownerID, agentID, keyID, at.UTC())
	if err != nil {
		return fmt.Errorf("custody authorization key is not pinned: %w", err)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || derived != keyID {
		return errors.New("custody authorization resolved key does not derive its key ID")
	}
	if err := resolver.Verify(context.Background(), mldsa44.UseCustodyAuthorization, digest[:], publicKey, proof); err != nil {
		return fmt.Errorf("custody authorization proof does not verify: %w", err)
	}
	return nil
}
