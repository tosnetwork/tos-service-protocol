//go:build linux

package mldsa44

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestExecutableSnapshotIsSealed checks that the bytes that execute cannot
// be changed after they were hashed: all four seals are set, and writes,
// growth and shrinking through a writable descriptor of the snapshot fail.
func TestExecutableSnapshotIsSealed(t *testing.T) {
	content := []byte("#!/bin/sh\nexit 0\n")
	path := filepath.Join(t.TempDir(), "tosctl")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	pin := hex.EncodeToString(sum[:])
	snapshot, err := pinExecutable(path, pin)
	if err != nil {
		t.Fatal(err)
	}
	file, err := snapshot.executable()
	if err != nil {
		t.Fatal(err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredSeals != requiredSeals {
		t.Fatalf("snapshot seals = %#x, %v", seals, err)
	}
	writable, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", file.Fd()), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen the snapshot for writing: %v", err)
	}
	defer writable.Close()
	if _, err := writable.WriteAt([]byte("X"), 0); err == nil {
		t.Fatal("the snapshot accepted an overwrite")
	}
	if _, err := writable.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := writable.Write([]byte("appended")); err == nil {
		t.Fatal("the snapshot accepted an append")
	}
	if err := writable.Truncate(int64(len(content)) + 1); err == nil {
		t.Fatal("the snapshot grew")
	}
	if err := writable.Truncate(1); err == nil {
		t.Fatal("the snapshot shrank")
	}
	// Rewriting the source file leaves the snapshot's bytes as hashed.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil || hex.EncodeToString(hash.Sum(nil)) != pin {
		t.Fatal("the snapshot's bytes changed")
	}
}
