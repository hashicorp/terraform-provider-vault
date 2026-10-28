// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

// newTestVaultClient starts an httptest server backed by handler and returns a
// Vault API client pointed at it. The server is shut down via t.Cleanup.
func newTestVaultClient(t *testing.T, handler http.HandlerFunc) *api.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	cfg.MaxRetries = 0
	cli, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	return cli
}

// vaultStatusHandler returns an HTTP handler that replies to every request with
// a Vault logical-read response whose "order_status" field cycles through the
// provided statuses in order, returning the last status for all subsequent calls.
func vaultStatusHandler(statuses []string) http.HandlerFunc {
	var call atomic.Int32
	return func(w http.ResponseWriter, r *http.Request) {
		idx := int(call.Add(1)) - 1
		if idx >= len(statuses) {
			idx = len(statuses) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"order_status": statuses[idx],
			},
		})
	}
}

// ── isOrderStatusTerminal ─────────────────────────────────────────────────────

func TestIsOrderStatusTerminal(t *testing.T) {
	terminal := []string{"error", "expired", "revoked", "completed"}
	for _, s := range terminal {
		t.Run(s, func(t *testing.T) {
			if !isOrderStatusTerminal(s) {
				t.Errorf("isOrderStatusTerminal(%q) = false, want true", s)
			}
		})
	}

	nonTerminal := []string{"pending", "awaiting-challenge-fulfillment", "processing", "", "unknown"}
	for _, s := range nonTerminal {
		t.Run("non-terminal/"+s, func(t *testing.T) {
			if isOrderStatusTerminal(s) {
				t.Errorf("isOrderStatusTerminal(%q) = true, want false", s)
			}
		})
	}
}

// ── pollOrderStatus ───────────────────────────────────────────────────────────

const testPollTimeout = 5 * time.Second

func TestPollOrderStatus_successOnFirstAttempt(t *testing.T) {
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"awaiting-challenge-fulfillment"}))
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		testPollTimeout, time.Millisecond, []string{"awaiting-challenge-fulfillment"})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestPollOrderStatus_successAfterRetries(t *testing.T) {
	// First two calls return "pending", third returns the desired status.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"pending", "pending", "awaiting-challenge-fulfillment"}))
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		testPollTimeout, time.Millisecond, []string{"awaiting-challenge-fulfillment"})
	if err != nil {
		t.Fatalf("expected nil error after retries, got: %v", err)
	}
}

func TestPollOrderStatus_terminalStateAborts(t *testing.T) {
	// First call returns "pending", second hits a terminal state.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"pending", "error"}))
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		testPollTimeout, time.Millisecond, []string{"awaiting-challenge-fulfillment"})
	if err == nil {
		t.Fatal("expected an error for terminal state, got nil")
	}
	want := "terminal state 'error'"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Errorf("error %q does not contain %q", got, want)
	}
}

func TestPollOrderStatus_timeoutExpires(t *testing.T) {
	// Status stays "pending" indefinitely — never reaches desired state.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"pending"}))
	const timeout = 50 * time.Millisecond
	start := time.Now()
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		timeout, time.Millisecond, []string{"awaiting-challenge-fulfillment"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error after the timeout elapsed, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v is not context.DeadlineExceeded", err)
	}
	if want := "Last status: pending"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
	if elapsed > 2*time.Second {
		t.Errorf("polling took %v, expected it to stop near the %v timeout", elapsed, timeout)
	}
}

func TestPollOrderStatus_nonPositiveTimeoutUsesDefault(t *testing.T) {
	// A zero timeout must not expire immediately; the default is used instead.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"pending", "awaiting-challenge-fulfillment"}))
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		0, time.Millisecond, []string{"awaiting-challenge-fulfillment"})
	if err != nil {
		t.Fatalf("expected nil error with default timeout, got: %v", err)
	}
}

func TestPollOrderStatus_multipleDesiredStatuses(t *testing.T) {
	// "completed" is also an acceptable status for certificate polling.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"completed"}))
	err := pollOrderStatus(context.Background(), cli, "mount", "role", "order-1",
		testPollTimeout, time.Millisecond, []string{"completed", "awaiting-challenge-fulfillment"})
	if err != nil {
		t.Fatalf("expected nil error for 'completed' status, got: %v", err)
	}
}

func TestPollOrderStatus_contextCancellationInterruptsWait(t *testing.T) {
	// Use a long poll interval so only a ctx-aware wait can return promptly.
	cli := newTestVaultClient(t, vaultStatusHandler([]string{"pending"}))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	err := pollOrderStatus(ctx, cli, "mount", "role", "order-1",
		time.Minute, 30*time.Second, []string{"awaiting-challenge-fulfillment"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when context is cancelled, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v is not context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("cancellation took %v, expected prompt return", elapsed)
	}
}
