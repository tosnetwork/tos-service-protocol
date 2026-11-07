// Command tos-service-wallet reviews and signs tos_service_v1 action JSON.
// Controller keys are ML-DSA-44 keys held in tosctl custody; the command
// names controllers and never sees private key material.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativewallet"
	"google.golang.org/protobuf/encoding/protojson"
)

type namesFlag []string

func (p *namesFlag) String() string { return fmt.Sprint([]string(*p)) }
func (p *namesFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	var authority, counterparty namesFlag
	actionPath := flag.String("action", "", "absolute path to NativeActionV1 JSON")
	outputPath := flag.String("output", "", "optional output path; stdout when empty")
	tosctl := flag.String("tosctl", "", "absolute path of the tosctl binary that holds the controller keys")
	tosctlSHA256 := flag.String("tosctl-sha256", "", "lowercase hex SHA-256 of that tosctl binary")
	tosctlConfig := flag.String("tosctl-config", "", "absolute path of the tosctl configuration")
	flag.Var(&authority, "authority-controller", "tosctl registry controller name; repeat for multisig")
	flag.Var(&counterparty, "counterparty-controller", "tosctl registry controller for acceptance or new-policy possession; repeat for multisig")
	flag.Parse()

	action, err := loadAction(*actionPath)
	if err != nil {
		fail(err)
	}
	review, built, err := nativewallet.ReviewAction(action)
	if err != nil {
		fail(err)
	}
	if len(authority) == 0 {
		fail(errors.New("at least one authority controller is required"))
	}
	// The vault URL carries custody credentials, so it is read from the
	// environment tosctl itself uses rather than from a command-line flag.
	signer, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: *tosctl, SHA256: *tosctlSHA256,
		ConfigPath: *tosctlConfig, VaultURL: os.Getenv("VAULT_URL")})
	if err != nil {
		fail(err)
	}
	reviewJSON, _ := json.MarshalIndent(review, "", "  ")
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", reviewJSON)
	_, _ = fmt.Fprintf(os.Stderr, "Type the complete action hash to sign: ")
	if err := nativewallet.ConfirmHash(bufio.NewReader(os.Stdin), review.ActionHash); err != nil {
		fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	authoritySignatures, err := nativewallet.Sign(ctx, signer, built, authority)
	if err != nil {
		fail(err)
	}
	var counterpartySignatures []*nativev1.SignatureV1
	if len(counterparty) != 0 {
		counterpartySignatures, err = nativewallet.Sign(ctx, signer, built, counterparty)
		if err != nil {
			fail(err)
		}
	}
	submission := &nativev1.SignedNativeActionV1{Action: action,
		AuthoritySignatures: authoritySignatures, CounterpartySignatures: counterpartySignatures}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}).Marshal(submission)
	if err != nil {
		fail(err)
	}
	encoded = append(encoded, '\n')
	if *outputPath == "" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			fail(err)
		}
		return
	}
	if !filepath.IsAbs(*outputPath) || filepath.Clean(*outputPath) != *outputPath {
		fail(errors.New("output path must be absolute and clean"))
	}
	output, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(err)
	}
	if _, err := output.Write(encoded); err != nil {
		_ = output.Close()
		fail(err)
	}
	if err := output.Close(); err != nil {
		fail(err)
	}
}

func loadAction(path string) (*nativev1.NativeActionV1, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("action path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("action JSON must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var action nativev1.NativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &action); err != nil {
		return nil, err
	}
	return &action, nil
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
