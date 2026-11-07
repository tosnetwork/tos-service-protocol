//go:build !linux

package mldsa44

import (
	"errors"
	"os"
)

type executableSnapshot struct{}

var errUnsupportedHost = errors.New("the tosctl ML-DSA-44 helper runs only on Linux")

func pinExecutable(string, string) (*executableSnapshot, error) {
	return nil, errUnsupportedHost
}

func (*executableSnapshot) executable() (*os.File, error) {
	return nil, errUnsupportedHost
}
