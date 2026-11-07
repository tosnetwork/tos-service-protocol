package agentpacket

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const maxWireBytes = 2 << 20

type Receiver interface {
	Receive(context.Context, Packet) error
}

// Handler verifies a packet before invoking the application receiver. It has
// no catalog, relay, or Gateway state and accepts only one bounded JSON body.
func Handler(verifier mldsa44.Verifier, resolver AgentResolver, guard *ReplayGuard, receiver Receiver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maxWireBytes+1))
		if err != nil || len(body) == 0 || len(body) > maxWireBytes {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		packet, err := DecodeJSON(body)
		if err != nil || Verify(request.Context(), verifier, resolver, guard, packet, time.Now()) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if receiver == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := receiver.Receive(request.Context(), packet); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}

// Post sends a signed packet directly to a recipient endpoint. Redirects are
// disabled so credentials or packet bytes cannot silently cross origins.
func Post(ctx context.Context, client *http.Client, endpoint string, packet Packet) error {
	if ctx == nil || client == nil {
		return errors.New("invalid Agent packet HTTP client")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid Agent packet endpoint")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1")) {
		return errors.New("Agent packet endpoint must use HTTPS outside loopback")
	}
	wire, err := EncodeJSON(packet)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(wire)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	transportClient := *client
	transportClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transportClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusAccepted {
		return errors.New("Agent packet receiver rejected packet")
	}
	return nil
}
