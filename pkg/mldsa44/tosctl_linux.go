//go:build linux

package mldsa44

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// executableIdentity is what was hashed: the file the pin was checked
// against. A later open whose status matches it exactly (device, inode, size,
// modification and change times) is the same unmodified file and is not
// re-hashed; any difference forces a full re-hash against the pin.
type executableIdentity struct {
	device, inode   uint64
	size            int64
	modSec, modNsec int64
	chgSec, chgNsec int64
	owner, mode     uint32
	verified        bool
}

func identityOf(info os.FileInfo) (executableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return executableIdentity{}, errors.New("executable status is unavailable")
	}
	return executableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(),
		modSec: stat.Mtim.Sec, modNsec: stat.Mtim.Nsec, chgSec: stat.Ctim.Sec, chgNsec: stat.Ctim.Nsec,
		owner: stat.Uid, mode: stat.Mode, verified: true}, nil
}

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

func pinExecutable(path, pin string) (executableIdentity, error) {
	file, identity, err := openPinnedExecutable(path, pin, executableIdentity{})
	if err != nil {
		return executableIdentity{}, err
	}
	_ = file.Close()
	return identity, nil
}

// openPinnedExecutable opens path, checks it is the pinned binary and
// returns the open descriptor positioned at its start, ready to be executed
// through /proc/self/fd. The descriptor, not the path, is what runs.
func openPinnedExecutable(path, pin string, known executableIdentity) (*os.File, executableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, executableIdentity{}, errors.New("executable path is unavailable or a symbolic link")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, executableIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, executableIdentity{}, errors.New("executable changed while it was opened")
	}
	if err := checkExecutableFile(info); err != nil {
		_ = file.Close()
		return nil, executableIdentity{}, err
	}
	identity, err := identityOf(info)
	if err != nil {
		_ = file.Close()
		return nil, executableIdentity{}, err
	}
	if !known.verified || identity != known {
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			_ = file.Close()
			return nil, executableIdentity{}, err
		}
		if hex.EncodeToString(hash.Sum(nil)) != pin {
			_ = file.Close()
			return nil, executableIdentity{}, errors.New("executable does not match its SHA-256 pin")
		}
		after, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, executableIdentity{}, err
		}
		if afterIdentity, err := identityOf(after); err != nil || afterIdentity != identity {
			_ = file.Close()
			return nil, executableIdentity{}, errors.New("executable changed while it was hashed")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, executableIdentity{}, err
		}
	}
	return file, identity, nil
}
