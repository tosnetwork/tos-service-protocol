// Package mldsa44test provides test support for the ML-DSA-44 boundary:
// the real tosctl helper taken from the environment, a private tosctl vault
// with named controllers, and Fake, an in-process stand-in for pure-logic
// tests.
//
// Fake does not implement ML-DSA-44. Its "signatures" only prove to Fake that
// it produced them. Any test that checks real ML-DSA-44 bytes must use
// RequireTosctl or NewCustody, which fail the test when the helper is not
// configured rather than skipping it.
package mldsa44test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	// BinaryEnvironment names the absolute path of the tosctl helper.
	BinaryEnvironment = "TOS_SERVICE_TOSCTL"
	// SHA256Environment names the lowercase hex SHA-256 of that binary.
	SHA256Environment = "TOS_SERVICE_TOSCTL_SHA256"
)

var (
	helperOnce   sync.Once
	helperConfig mldsa44.TosctlConfig
	helper       *mldsa44.Tosctl
	helperErr    error
)

// RequireTosctl returns the verification-only helper configured by
// TOS_SERVICE_TOSCTL and TOS_SERVICE_TOSCTL_SHA256. A missing or wrong
// configuration fails the test: a conformance check that cannot run must not
// pass.
func RequireTosctl(t testing.TB) *mldsa44.Tosctl {
	t.Helper()
	helperOnce.Do(func() {
		helperConfig = mldsa44.TosctlConfig{Binary: os.Getenv(BinaryEnvironment), SHA256: os.Getenv(SHA256Environment)}
		if helperConfig.Binary == "" || helperConfig.SHA256 == "" {
			helperErr = errors.New(BinaryEnvironment + " and " + SHA256Environment +
				" must name the tosctl helper and its SHA-256; this test checks real ML-DSA-44 bytes and cannot be skipped")
			return
		}
		helper, helperErr = mldsa44.NewTosctl(helperConfig)
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	return helper
}

// Custody is a private tosctl vault holding named test controllers.
type Custody struct {
	Signer     *mldsa44.Tosctl
	PublicKeys map[string][]byte
}

// KeyID returns the text key ID of a named controller.
func (c *Custody) KeyID(t testing.TB, name string) string {
	t.Helper()
	key, ok := c.PublicKeys[name]
	if !ok {
		t.Fatalf("unknown test controller %q", name)
	}
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return mldsa44.KeyIDText(id)
}

// NewCustody creates a private file vault and configuration for the real
// helper, creates one ML-DSA-44 controller per name in it, and returns a
// signing helper. The vault is removed when the test ends.
func NewCustody(t testing.TB, names ...string) *Custody {
	t.Helper()
	RequireTosctl(t)
	// tosctl refuses a vault in a directory others can modify, so the
	// directory is created owner-private directly under the temp root.
	directory, err := os.MkdirTemp("", "tos-mldsa44-custody-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	vaultURL := "file://" + filepath.Join(directory, "vault.json") + "?master_key=" + hex.EncodeToString(masterKey)
	configPath := filepath.Join(directory, "tosctl-config.json")
	runHelper(t, vaultURL, "config", "generate", "--output="+configPath)
	custody := &Custody{PublicKeys: make(map[string][]byte, len(names))}
	for _, name := range names {
		output := runHelper(t, vaultURL, "agent", "native-registry", "new-controller", "--config", configPath,
			"--name", name, "--format", "json")
		var created struct {
			Name      string `json:"name"`
			Suite     string `json:"suite"`
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		}
		if err := json.Unmarshal(output, &created); err != nil || created.Name != name || created.Suite != "ML-DSA-44" {
			t.Fatalf("unexpected new-controller output for %q: %s", name, output)
		}
		key, err := hex.DecodeString(created.PublicKey)
		if err != nil || len(key) != mldsa44.PublicKeySize {
			t.Fatalf("new-controller returned a malformed key for %q", name)
		}
		id, err := mldsa44.KeyID(key)
		if err != nil || hex.EncodeToString(id[:]) != created.KeyID {
			t.Fatalf("new-controller key ID for %q does not match its key", name)
		}
		custody.PublicKeys[name] = key
	}
	config := helperConfig
	config.ConfigPath = configPath
	config.VaultURL = vaultURL
	signer, err := mldsa44.NewTosctl(config)
	if err != nil {
		t.Fatal(err)
	}
	custody.Signer = signer
	return custody
}

// runHelper runs a custody setup command. Only test setup calls the binary by
// path; signing and verification go through the pinned Tosctl type.
func runHelper(t testing.TB, vaultURL string, args ...string) []byte {
	t.Helper()
	command := exec.Command(helperConfig.Binary, args...)
	command.Env = []string{"VAULT_URL=" + vaultURL}
	command.Dir = "/"
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("tosctl %v: %v: %s", args, err, exitErr.Stderr)
		}
		t.Fatalf("tosctl %v: %v", args, err)
	}
	return output
}

// Fake is an in-process stand-in for the helper in pure-logic tests. It is
// not ML-DSA-44: its keys are derived from controller names and its
// signatures are hashes that only Fake accepts. Never use it where real
// ML-DSA-44 bytes are being checked.
type Fake struct {
	mu    sync.Mutex
	calls int
}

// PublicKey returns the fake public key of a named controller.
func (f *Fake) PublicKey(name string) []byte {
	return expand("fake-mldsa44-public-key", []byte(name), mldsa44.PublicKeySize)
}

// KeyID returns the text key ID of a named fake controller.
func (f *Fake) KeyID(name string) string {
	id, _ := mldsa44.KeyID(f.PublicKey(name))
	return mldsa44.KeyIDText(id)
}

// Calls reports how many Verify and Sign calls Fake answered.
func (f *Fake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Sign implements mldsa44.Signer.
func (f *Fake) Sign(_ context.Context, controller string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	f.count()
	publicKey := f.PublicKey(controller)
	signature, err := fakeSignature(use, payload, publicKey)
	if err != nil {
		return mldsa44.Signature{}, err
	}
	id, _ := mldsa44.KeyID(publicKey)
	return mldsa44.Signature{KeyID: id, PublicKey: publicKey, Signature: signature}, nil
}

// Verify implements mldsa44.Verifier.
func (f *Fake) Verify(_ context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	f.count()
	if len(publicKey) != mldsa44.PublicKeySize || len(signature) != mldsa44.SignatureSize {
		return mldsa44.ErrMalformed
	}
	expected, err := fakeSignature(use, payload, publicKey)
	if err != nil {
		return err
	}
	if string(expected) != string(signature) {
		return mldsa44.ErrInvalidSignature
	}
	return nil
}

func (f *Fake) count() {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
}

func fakeSignature(use mldsa44.Use, payload, publicKey []byte) ([]byte, error) {
	contextName, err := use.Context()
	if err != nil {
		return nil, mldsa44.ErrMalformed
	}
	message := payload
	if use == mldsa44.UseRegistry {
		root, err := cell.FromBOC(payload)
		if err != nil || root == nil {
			return nil, mldsa44.ErrMalformed
		}
		message = root.Hash()
	}
	seed := sha256.New()
	for _, part := range [][]byte{[]byte(contextName), publicKey, message} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = seed.Write(length[:])
		_, _ = seed.Write(part)
	}
	return expand("fake-mldsa44-signature", seed.Sum(nil), mldsa44.SignatureSize), nil
}

func expand(domain string, seed []byte, size int) []byte {
	out := make([]byte, 0, size+sha256.Size)
	for counter := uint32(0); len(out) < size; counter++ {
		hash := sha256.New()
		_, _ = hash.Write([]byte(domain))
		_, _ = hash.Write(seed)
		var block [4]byte
		binary.BigEndian.PutUint32(block[:], counter)
		_, _ = hash.Write(block[:])
		out = hash.Sum(out)
	}
	return out[:size]
}
