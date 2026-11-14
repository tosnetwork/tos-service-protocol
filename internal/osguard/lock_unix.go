//go:build !windows

package osguard

import (
	"errors"
	"os"
	"syscall"
)

func WithExclusiveFileLock(path string, permission os.FileMode, fn func() error) error {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, permission)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// TryExclusiveFileLock takes an exclusive lock without waiting. acquired is
// false, with a nil error, only when another open file description holds
// the lock. The caller releases an acquired lock with release.
func TryExclusiveFileLock(path string, permission os.FileMode) (release func(), acquired bool, err error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, permission)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
	}, true, nil
}
