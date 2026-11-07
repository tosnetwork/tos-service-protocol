//go:build linux

package mldsa44

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxExecutableBytes bounds the helper binary copied into a snapshot.
const maxExecutableBytes = 2 << 30

const requiredSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

// executableSnapshot is a sealed in-memory copy of the pinned binary. Its
// bytes are the ones that were hashed, and the seals make them immutable, so
// what executes is exactly what matched the pin, whatever later happens to
// the file at the configured path.
type executableSnapshot struct {
	file *os.File
}

var (
	snapshotMu    sync.Mutex
	snapshotCache = map[string]*executableSnapshot{}
)

// checkExecutableFile refuses anything but a regular executable file that no
// one but its owner can write, owned by root or by the current user.
func checkExecutableFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("executable is not a regular executable file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("executable is writable by its group or by others")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) {
		return errors.New("executable must be owned by root or by the current user")
	}
	return nil
}

// pinExecutable returns the sealed snapshot of the binary at path whose
// bytes hash to pin. Snapshots are shared within the process per path and
// pin, so a large binary is copied once.
func pinExecutable(path, pin string) (*executableSnapshot, error) {
	snapshotMu.Lock()
	defer snapshotMu.Unlock()
	key := path + "\x00" + pin
	if snapshot, ok := snapshotCache[key]; ok {
		return snapshot, nil
	}
	snapshot, err := snapshotExecutable(path, pin)
	if err != nil {
		return nil, err
	}
	snapshotCache[key] = snapshot
	return snapshot, nil
}

func snapshotExecutable(path, pin string) (*executableSnapshot, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("executable path is unavailable or a symbolic link")
	}
	source, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		return nil, errors.New("executable changed while it was opened")
	}
	if err := checkExecutableFile(info); err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > maxExecutableBytes {
		return nil, errors.New("executable size is outside bounds")
	}
	fd, err := unix.MemfdCreate("tos-mldsa44-helper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		// Kernels before 6.3 do not know MFD_EXEC; their memfds are executable.
		fd, err = unix.MemfdCreate("tos-mldsa44-helper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, fmt.Errorf("create executable snapshot: %w", err)
	}
	writable := os.NewFile(uintptr(fd), "tos-mldsa44-helper")
	defer writable.Close()
	copied, err := io.Copy(writable, io.LimitReader(source, maxExecutableBytes+1))
	if err != nil || copied != info.Size() {
		return nil, errors.New("copy the executable into its snapshot")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, requiredSeals); err != nil {
		return nil, fmt.Errorf("seal the executable snapshot: %w", err)
	}
	if seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0); err != nil || seals&requiredSeals != requiredSeals {
		return nil, errors.New("the executable snapshot is not sealed")
	}
	// A read-only descriptor is what executes: execve refuses a file that has
	// a writable descriptor open, and the writable one is closed on return.
	readOnly, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("reopen the executable snapshot: %w", err)
	}
	hash := sha256.New()
	hashed, err := io.Copy(hash, readOnly)
	if err != nil || hashed != copied || hex.EncodeToString(hash.Sum(nil)) != pin {
		_ = readOnly.Close()
		return nil, errors.New("executable does not match its SHA-256 pin")
	}
	return &executableSnapshot{file: readOnly}, nil
}

// executable returns the sealed snapshot to execute.
func (s *executableSnapshot) executable() (*os.File, error) {
	if s == nil || s.file == nil {
		return nil, errors.New("executable snapshot is unavailable")
	}
	return s.file, nil
}
