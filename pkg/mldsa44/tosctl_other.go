//go:build !linux

package mldsa44

import (
	"errors"
	"os"
)

type executableIdentity struct{}

var errUnsupportedHost = errors.New("the tosctl ML-DSA-44 helper runs only on Linux")

func pinExecutable(string, string) (executableIdentity, error) {
	return executableIdentity{}, errUnsupportedHost
}

func openPinnedExecutable(string, string, executableIdentity) (*os.File, executableIdentity, error) {
	return nil, executableIdentity{}, errUnsupportedHost
}
