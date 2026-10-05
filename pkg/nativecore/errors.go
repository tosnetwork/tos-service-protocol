package nativecore

import (
	"errors"
	"fmt"
)

// ErrorCode is the stable tos_service_v1 validation code. The numeric values
// intentionally match the Native Registry TVM exit codes so clients can use a
// single vocabulary before and after submission.
type ErrorCode uint16

const (
	ErrBadMessage         ErrorCode = 2200
	ErrWrongNetwork       ErrorCode = 2201
	ErrWrongContract      ErrorCode = 2202
	ErrBadAction          ErrorCode = 2203
	ErrBadPredecessor     ErrorCode = 2204
	ErrBadSequence        ErrorCode = 2205
	ErrTombstoned         ErrorCode = 2206
	ErrBadPolicy          ErrorCode = 2207
	ErrBadSignature       ErrorCode = 2208
	ErrThreshold          ErrorCode = 2209
	ErrBadTransition      ErrorCode = 2210
	ErrImmutableVersion   ErrorCode = 2211
	ErrTimelock           ErrorCode = 2212
	ErrDuplicateSignature ErrorCode = 2213
	ErrWeakKey            ErrorCode = 2214
	ErrPolicyTooWide      ErrorCode = 2215
)

var errorNames = map[ErrorCode]string{
	ErrBadMessage:         "NATIVE_BAD_MESSAGE",
	ErrWrongNetwork:       "NATIVE_WRONG_NETWORK",
	ErrWrongContract:      "NATIVE_WRONG_CONTRACT",
	ErrBadAction:          "NATIVE_BAD_ACTION",
	ErrBadPredecessor:     "NATIVE_BAD_PREDECESSOR",
	ErrBadSequence:        "NATIVE_BAD_SEQUENCE",
	ErrTombstoned:         "NATIVE_TOMBSTONED",
	ErrBadPolicy:          "NATIVE_BAD_POLICY",
	ErrBadSignature:       "NATIVE_BAD_SIGNATURE",
	ErrThreshold:          "NATIVE_THRESHOLD",
	ErrBadTransition:      "NATIVE_BAD_TRANSITION",
	ErrImmutableVersion:   "NATIVE_IMMUTABLE_VERSION",
	ErrTimelock:           "NATIVE_TIMELOCK",
	ErrDuplicateSignature: "NATIVE_DUPLICATE_SIGNATURE",
	ErrWeakKey:            "NATIVE_WEAK_KEY",
	ErrPolicyTooWide:      "NATIVE_POLICY_TOO_WIDE",
}

func (c ErrorCode) String() string {
	if name, ok := errorNames[c]; ok {
		return name
	}
	return fmt.Sprintf("NATIVE_ERROR_%d", c)
}

// ProtocolError preserves a stable code while retaining a human-readable
// diagnostic. Consumers must branch on Code, never on Message.
type ProtocolError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return e.Code.String()
	}
	return e.Code.String() + ": " + e.Message
}

func (e *ProtocolError) Unwrap() error { return e.Cause }

// ErrorCodeOf returns a stable protocol code for errors emitted by nativecore.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		return 0, false
	}
	return protocolErr.Code, true
}

// NewProtocolError lets chain adapters preserve the Native error vocabulary
// without depending on diagnostic strings.
func NewProtocolError(code ErrorCode, message string, cause error) error {
	if existing, ok := ErrorCodeOf(cause); ok && existing != 0 {
		return cause
	}
	return &ProtocolError{Code: code, Message: message, Cause: cause}
}

func nativeError(code ErrorCode, message string) error {
	return &ProtocolError{Code: code, Message: message}
}

func wrapNativeError(code ErrorCode, message string, cause error) error {
	if cause == nil {
		return nil
	}
	var protocolErr *ProtocolError
	if errors.As(cause, &protocolErr) {
		return cause
	}
	return &ProtocolError{Code: code, Message: message, Cause: cause}
}
