package mldsa44

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	// DefaultHelperTimeout bounds one helper invocation when TosctlConfig
	// leaves Timeout unset.
	DefaultHelperTimeout = time.Minute
	// MaxHelperTimeout is the largest admitted Timeout.
	MaxHelperTimeout = 10 * time.Minute
	// MaxActionBOCBytes bounds a registry action BOC handed to the helper.
	MaxActionBOCBytes = 64 << 10
	// MaxMessageBytes bounds an Agent packet or contact preimage. The
	// preimage travels as one hex argument, which must stay well inside the
	// kernel's per-argument limit.
	MaxMessageBytes = 16 << 10

	maxHelperStdout = 64 << 10
	maxHelperStderr = 16 << 10
)

var (
	controllerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sha256HexPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// TosctlConfig configures the tosctl helper. Binary and SHA256 are always
// required; ConfigPath and VaultURL are required only for signing, where
// tosctl reaches the controller keys it holds in its vault.
type TosctlConfig struct {
	// Binary is the absolute, clean path of the tosctl executable.
	Binary string `json:"binary"`
	// SHA256 is the lowercase hex SHA-256 of the executable's bytes. The
	// helper refuses to run any other file.
	SHA256 string `json:"sha256"`
	// ConfigPath is the absolute, clean path of the tosctl configuration
	// file used for signing.
	ConfigPath string `json:"config_path,omitempty"`
	// VaultURL is handed to tosctl as its only environment variable when
	// signing. It names custody; it is not key material.
	VaultURL string `json:"vault_url,omitempty"`
	// Timeout bounds one invocation; zero means DefaultHelperTimeout.
	Timeout time.Duration `json:"-"`
}

// Tosctl runs a pinned tosctl binary for ML-DSA-44 signing and verification.
// The binary is identified by its SHA-256, and every invocation executes the
// already-opened, verified file descriptor, so replacing the file at its path
// cannot substitute another program. No shell is involved and the child gets
// an empty environment (only VAULT_URL when signing).
type Tosctl struct {
	config TosctlConfig
	mu     sync.Mutex
	pinned executableIdentity
}

// NewTosctl checks the configuration and the binary's pin.
func NewTosctl(config TosctlConfig) (*Tosctl, error) {
	if !filepath.IsAbs(config.Binary) || filepath.Clean(config.Binary) != config.Binary {
		return nil, errors.New("tosctl helper binary path must be absolute and clean")
	}
	if !sha256HexPattern.MatchString(config.SHA256) {
		return nil, errors.New("tosctl helper SHA-256 pin must be 64 lowercase hex characters")
	}
	if config.ConfigPath != "" && (!filepath.IsAbs(config.ConfigPath) || filepath.Clean(config.ConfigPath) != config.ConfigPath) {
		return nil, errors.New("tosctl helper config path must be absolute and clean")
	}
	if (config.ConfigPath == "") != (config.VaultURL == "") {
		return nil, errors.New("tosctl helper signing needs both a config path and a vault URL")
	}
	if strings.ContainsAny(config.VaultURL, "\x00\n") {
		return nil, errors.New("invalid tosctl helper vault URL")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultHelperTimeout
	}
	if config.Timeout < 0 || config.Timeout > MaxHelperTimeout {
		return nil, errors.New("tosctl helper timeout is outside bounds")
	}
	identity, err := pinExecutable(config.Binary, config.SHA256)
	if err != nil {
		return nil, fmt.Errorf("tosctl helper binary: %w", err)
	}
	return &Tosctl{config: config, pinned: identity}, nil
}

// CanSign reports whether the helper was configured with signing custody.
func (t *Tosctl) CanSign() bool { return t != nil && t.config.ConfigPath != "" }

type verifyResponse struct {
	Valid   bool   `json:"valid"`
	Suite   string `json:"suite"`
	Context string `json:"context"`
	KeyID   string `json:"key_id"`
}

type signResponse struct {
	Suite      string `json:"suite"`
	Context    string `json:"context"`
	MessageHex string `json:"message_hex"`
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

// Verify checks one signature through the helper. A helper that exits
// non-zero is reported as ErrInvalidSignature; a helper that cannot be run or
// answers in an unexpected shape is ErrUnavailable. Neither is ever success.
func (t *Tosctl) Verify(ctx context.Context, use Use, payload, publicKey, signature []byte) error {
	if t == nil || ctx == nil {
		return ErrUnavailable
	}
	contextName, err := use.Context()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return ErrMalformed
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		return err
	}
	args := []string{"agent", "native-registry", "verify", "--for", string(use)}
	payloadFile, payloadArgs, err := payloadArguments(use, payload)
	if err != nil {
		return err
	}
	if payloadFile != nil {
		defer payloadFile.Close()
	}
	args = append(args, payloadArgs...)
	args = append(args, "--public-key-hex", hex.EncodeToString(publicKey),
		"--signature-hex", hex.EncodeToString(signature), "--format", "json")
	stdout, exited, err := t.run(ctx, []string{}, payloadFile, args)
	if err != nil {
		if exited {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
		return err
	}
	var response verifyResponse
	if err := decodeStrict(stdout, &response); err != nil || !response.Valid || response.Suite != "ML-DSA-44" ||
		response.Context != contextName || response.KeyID != hex.EncodeToString(keyID[:]) {
		return fmt.Errorf("%w: unexpected verification response", ErrUnavailable)
	}
	return nil
}

// Sign asks tosctl to sign with the vault-held controller named controller.
// The response is checked for the requested context, the exact signed
// message, key and signature lengths, and a key ID that matches the key.
func (t *Tosctl) Sign(ctx context.Context, controller string, use Use, payload []byte) (Signature, error) {
	if t == nil || ctx == nil || !t.CanSign() {
		return Signature{}, fmt.Errorf("%w: signing custody is not configured", ErrUnavailable)
	}
	if !controllerNamePattern.MatchString(controller) {
		return Signature{}, fmt.Errorf("%w: invalid controller name", ErrMalformed)
	}
	contextName, err := use.Context()
	if err != nil {
		return Signature{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	expectedMessage, err := signedMessage(use, payload)
	if err != nil {
		return Signature{}, err
	}
	payloadFile, payloadArgs, err := payloadArguments(use, payload)
	if err != nil {
		return Signature{}, err
	}
	if payloadFile != nil {
		defer payloadFile.Close()
	}
	args := []string{"agent", "native-registry", "sign", "--config", t.config.ConfigPath,
		"--controller", controller, "--for", string(use)}
	args = append(args, payloadArgs...)
	args = append(args, "--format", "json")
	stdout, _, err := t.run(ctx, []string{"VAULT_URL=" + t.config.VaultURL}, payloadFile, args)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var response signResponse
	if err := decodeStrict(stdout, &response); err != nil || response.Suite != "ML-DSA-44" ||
		response.Context != contextName || response.MessageHex != hex.EncodeToString(expectedMessage) {
		return Signature{}, fmt.Errorf("%w: unexpected signing response", ErrUnavailable)
	}
	publicKey, keyErr := decodeHex(response.PublicKey, PublicKeySize)
	signature, signatureErr := decodeHex(response.Signature, SignatureSize)
	keyID, idErr := decodeHex(response.KeyID, KeyIDSize)
	if keyErr != nil || signatureErr != nil || idErr != nil {
		return Signature{}, fmt.Errorf("%w: malformed signing response", ErrUnavailable)
	}
	result := Signature{PublicKey: publicKey, Signature: signature}
	copy(result.KeyID[:], keyID)
	if err := CheckSignature(result); err != nil {
		return Signature{}, fmt.Errorf("%w: signing response key ID does not match its key", ErrUnavailable)
	}
	return result, nil
}

// signedMessage is the message the helper reports it signed: the action
// cell hash for a registry action, the preimage itself otherwise.
func signedMessage(use Use, payload []byte) ([]byte, error) {
	if use != UseRegistry {
		if len(payload) == 0 || len(payload) > MaxMessageBytes {
			return nil, ErrMalformed
		}
		return payload, nil
	}
	root, err := actionCell(payload)
	if err != nil {
		return nil, err
	}
	return root.Hash(), nil
}

func actionCell(boc []byte) (*cell.Cell, error) {
	if len(boc) == 0 || len(boc) > MaxActionBOCBytes {
		return nil, ErrMalformed
	}
	roots, err := cell.FromBOCMultiRoot(boc)
	if err != nil || len(roots) != 1 || roots[0] == nil {
		return nil, ErrMalformed
	}
	return roots[0], nil
}

// payloadArguments returns the helper arguments that carry the payload and,
// for a registry action, an unlinked file holding its BOC that the child
// reads as descriptor 3.
func payloadArguments(use Use, payload []byte) (*os.File, []string, error) {
	if use != UseRegistry {
		if len(payload) == 0 || len(payload) > MaxMessageBytes {
			return nil, nil, ErrMalformed
		}
		return nil, []string{"--message-hex", hex.EncodeToString(payload)}, nil
	}
	if _, err := actionCell(payload); err != nil {
		return nil, nil, err
	}
	file, err := unlinkedFile(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return file, []string{"--action-boc", "/dev/fd/3"}, nil
}

func unlinkedFile(content []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "tos-mldsa44-payload-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// run executes the pinned helper. exited reports that the helper ran and
// exited with a non-zero status, as opposed to never running or timing out.
func (t *Tosctl) run(ctx context.Context, environment []string, payload *os.File, args []string) ([]byte, bool, error) {
	executable, err := t.openExecutable()
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer executable.Close()
	extra := []*os.File{executable}
	if payload != nil {
		extra = []*os.File{payload, executable}
	}
	ctx, cancel := context.WithTimeout(ctx, t.config.Timeout)
	defer cancel()
	command := exec.CommandContext(ctx, fmt.Sprintf("/proc/self/fd/%d", 2+len(extra)), args...)
	command.ExtraFiles = extra
	command.Env = environment
	command.Dir = "/"
	command.WaitDelay = 5 * time.Second
	stdout := limitedBuffer{limit: maxHelperStdout}
	stderr := limitedBuffer{limit: maxHelperStderr}
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	if ctx.Err() != nil {
		return nil, false, fmt.Errorf("%w: helper timed out or was cancelled", ErrUnavailable)
	}
	if stdout.overflow || stderr.overflow {
		return nil, false, fmt.Errorf("%w: helper output exceeds its bound", ErrUnavailable)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.Exited() {
			return nil, true, fmt.Errorf("tosctl exited with status %d: %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return nil, false, fmt.Errorf("%w: %v", ErrUnavailable, runErr)
	}
	return stdout.Bytes(), false, nil
}

func (t *Tosctl) openExecutable() (*os.File, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	file, identity, err := openPinnedExecutable(t.config.Binary, t.config.SHA256, t.pinned)
	if err != nil {
		return nil, err
	}
	t.pinned = identity
	return file, nil
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing helper output")
	}
	return nil
}

func decodeHex(value string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != size || value != hex.EncodeToString(raw) {
		return nil, ErrMalformed
	}
	return raw, nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.buffer.Len()
	if len(data) > remaining {
		if remaining > 0 {
			_, _ = b.buffer.Write(data[:remaining])
		}
		b.overflow = true
		return original, nil
	}
	_, _ = b.buffer.Write(data)
	return original, nil
}

func (b *limitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedBuffer) String() string { return b.buffer.String() }
