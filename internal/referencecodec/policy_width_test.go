package referencecodec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// referenceKey is a deterministic 1,312-byte stand-in for an ML-DSA-44 key.
// Policy encoding never parses the key, so any bytes of the right length
// exercise the layout.
func referenceKey(i int) string {
	var key []byte
	for block := 0; len(key) < publicKeyBytes; block++ {
		digest := sha256.Sum256([]byte(fmt.Sprintf("reference-policy-width-%d-%d", i, block)))
		key = append(key, digest[:]...)
	}
	return hex.EncodeToString(key[:publicKeyBytes])
}

func referenceController(i int) Controller {
	key := referenceKey(i)
	raw, _ := hex.DecodeString(key)
	id := controllerKeyID(raw)
	return Controller{PublicKeyHex: key, KeyID: "mldsa44:" + hex.EncodeToString(id[:]), Weight: 1, PurposeMask: 15, Recovery: true}
}

func referencePolicy(width int) Policy {
	policy := Policy{Threshold: 1, RecoveryThreshold: 1}
	for i := range width {
		policy.Controllers = append(policy.Controllers, referenceController(i))
	}
	return policy
}

// The Native Registry admits at most 8 controllers and refuses a wider
// policy with exit code 2215.
func TestReferencePolicyWidthMatchesTheRegistry(t *testing.T) {
	if _, err := policyCell(referencePolicy(8)); err != nil {
		t.Fatalf("a policy at the Registry width was refused: %v", err)
	}
	_, err := policyCell(referencePolicy(9))
	if code, ok := ErrorCodeOf(err); !ok || code != 2215 {
		t.Fatalf("a policy one controller too wide: code %d, %v", code, err)
	}
}

func TestReferencePolicyRefusesInconsistentControllers(t *testing.T) {
	for name, mutate := range map[string]func(*Controller){
		"short key":       func(c *Controller) { c.PublicKeyHex = c.PublicKeyHex[:64] },
		"long key":        func(c *Controller) { c.PublicKeyHex += "00" },
		"uppercase key":   func(c *Controller) { c.PublicKeyHex = strings.ToUpper(c.PublicKeyHex) },
		"other key ID":    func(c *Controller) { c.KeyID = referenceController(7).KeyID },
		"Ed25519 key ID":  func(c *Controller) { c.KeyID = "ed25519:" + strings.TrimPrefix(c.KeyID, "mldsa44:") },
		"missing key ID":  func(c *Controller) { c.KeyID = "" },
		"recovery flag":   func(c *Controller) { c.Recovery = false },
		"unknown purpose": func(c *Controller) { c.PurposeMask = 16 },
	} {
		policy := referencePolicy(2)
		mutate(&policy.Controllers[0])
		if _, err := policyCell(policy); err == nil {
			t.Fatalf("%s accepted", name)
		} else if code, _ := ErrorCodeOf(err); code != 2207 {
			t.Fatalf("%s: code %d", name, code)
		}
	}
	duplicate := referencePolicy(1)
	duplicate.Controllers = append(duplicate.Controllers, duplicate.Controllers[0])
	if _, err := policyCell(duplicate); err == nil {
		t.Fatal("duplicate controller accepted")
	}
	isolated := referencePolicy(1)
	isolated.Controllers[0].PurposeMask, isolated.Controllers[0].Recovery = 1|4, true
	if _, err := policyCell(isolated); err == nil {
		t.Fatal("a threshold no delegation or Capability controller can reach was accepted")
	}
}

func TestReferenceStoredMaterialChain(t *testing.T) {
	data := make([]byte, signatureBytes)
	for i := range data {
		data[i] = byte(i)
	}
	stored := storedMaterial(data)
	s := stored.MustBeginParse()
	if s.MustLoadUInt(32) != signatureBytes || s.RefsNum() != 1 {
		t.Fatal("stored wrapper layout")
	}
	cells, total := 0, 0
	for current := s.MustLoadRef(); ; {
		bits := current.BitsLeft()
		total += int(bits / 8)
		cells++
		if current.RefsNum() == 0 {
			if bits/8 != signatureBytes%chainCellBytes {
				t.Fatalf("final chain cell holds %d bytes", bits/8)
			}
			break
		}
		if bits != chainCellBytes*8 {
			t.Fatalf("chain cell %d holds %d bits", cells, bits)
		}
		current.MustLoadSlice(bits)
		current = current.MustLoadRef()
	}
	if total != signatureBytes || cells != signatureBytes/chainCellBytes+1 {
		t.Fatalf("chain carries %d bytes in %d cells", total, cells)
	}
}
