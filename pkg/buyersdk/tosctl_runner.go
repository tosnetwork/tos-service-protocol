package buyersdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type commandRunner interface {
	run(context.Context, string, ...string) ([]byte, error)
}

func validCellDigest(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func parseRawAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil, errors.New("invalid raw workchain-zero address")
	}
	return parsed, nil
}

func isRawAddress(value string) bool {
	_, err := parseRawAddress(value)
	return err == nil
}

func sameAddress(left, right string) bool {
	a, errA := parseAnyAddress(left)
	b, errB := parseAnyAddress(right)
	return errA == nil && errB == nil && a.Workchain() == b.Workchain() && bytes.Equal(a.Data(), b.Data())
}

func parseAnyAddress(value string) (*address.Address, error) {
	if parsed, err := address.ParseRawAddr(value); err == nil {
		return parsed, nil
	}
	return address.ParseAddr(value)
}

func secureExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o022 == 0 && info.Mode().Perm()&0o111 != 0 && osguard.TrustedExecutableOwner(info)
}

func secureConfigFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && osguard.CurrentUserOwns(info)
}

type executableIdentity struct {
	size   int64
	digest [sha256.Size]byte
}

type execRunner struct {
	identity    executableIdentity
	config      []byte
	environment []string
	extraArgs   []string
}

func newPinnedExecRunner(binaryPath, configPath string) (*execRunner, error) {
	return newPinnedExecRunnerWithVault(binaryPath, configPath, "")
}

func newPinnedExecRunnerWithVault(binaryPath, configPath, vaultURL string) (*execRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("descriptor-pinned tosctl custody is supported only on Linux")
	}
	executable, identity, err := openAndIdentifyExecutable(binaryPath)
	if err != nil {
		return nil, err
	}
	_ = executable.Close()
	config, err := os.ReadFile(configPath)
	if err != nil || len(config) == 0 || len(config) > 2<<20 {
		return nil, errors.New("read bounded tosctl custody configuration")
	}
	environment := []string{}
	if vaultURL != "" {
		if len(vaultURL) > 4096 || strings.ContainsRune(vaultURL, '\x00') ||
			(!strings.HasPrefix(vaultURL, "file://") && !strings.HasPrefix(vaultURL, "hashicorp://")) {
			return nil, errors.New("invalid bounded tosctl vault URL")
		}
		environment = []string{"VAULT_URL=" + vaultURL}
	}
	return &execRunner{identity: identity, config: append([]byte(nil), config...), environment: environment}, nil
}

func (r *execRunner) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("tosctl custody runner is unavailable")
	}
	executable, identity, err := openAndIdentifyExecutable(binary)
	if err != nil || identity != r.identity {
		if executable != nil {
			_ = executable.Close()
		}
		return nil, errors.New("enrolled tosctl executable identity changed")
	}
	defer executable.Close()
	config, err := pinnedDescriptor(r.config)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	args = append(args, r.extraArgs...)
	args = append(args, "--config-fd", "3", "--config-format", "json")
	command := exec.CommandContext(ctx, "/proc/self/fd/4", args...)
	command.ExtraFiles = []*os.File{config, executable}
	// Custody must not inherit loader, proxy, HOME, PATH, certificate, or
	// wallet-selection variables from the long-running caller process.
	command.Env = r.childEnvironment()
	output := cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	return output.Bytes(), err
}

// childEnvironment is the complete environment custody runs with: only the
// configured VAULT_URL, if any. It is never nil, because exec.Cmd treats a
// nil Env as "inherit the parent's environment".
func (r *execRunner) childEnvironment() []string {
	return append(make([]string, 0, len(r.environment)), r.environment...)
}

func openAndIdentifyExecutable(path string) (*os.File, executableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 || pathInfo.Mode().Perm()&0o022 != 0 {
		return nil, executableIdentity{}, errors.New("invalid tosctl executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, executableIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !osguard.TrustedExecutableOwner(info) {
		file.Close()
		return nil, executableIdentity{}, errors.New("tosctl executable identity is untrusted")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, executableIdentity{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	identity := executableIdentity{size: info.Size(), digest: digest}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, executableIdentity{}, err
	}
	return file, identity, nil
}

func pinnedDescriptor(raw []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "tosctl-custody-config-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, errors.New("tosctl output exceeded limit")
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, errors.New("tosctl output exceeded limit")
	}
	return b.Buffer.Write(value)
}

func decodeSingleCell(encoded string) (*cell.Cell, error) {
	if encoded == "" || strings.Join(strings.Fields(encoded), "") != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	value, err := cell.FromBOC(raw)
	if err != nil {
		return nil, errors.New("invalid cell BOC")
	}
	return value, nil
}

func cellHash(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func decodeStateInit(encoded string) (*cell.Cell, string, error) {
	value, err := decodeSingleCell(encoded)
	if err != nil {
		return nil, "", err
	}
	return value, cellHash(value), nil
}
