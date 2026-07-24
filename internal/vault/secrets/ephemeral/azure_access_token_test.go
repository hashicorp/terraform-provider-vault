// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestAzureAccessToken(t *testing.T) {
	t.Helper()

	oldBaseURL := azureAccessTokenBaseURL
	oldDoer := azureTokenRequestDoer
	t.Cleanup(func() {
		azureAccessTokenBaseURL = oldBaseURL
		azureTokenRequestDoer = oldDoer
	})

	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if want := "/tenant-123/oauth2/v2.0/token"; r.URL.Path != want {
			t.Fatalf("path = %s, want %s", r.URL.Path, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %s, want application/x-www-form-urlencoded", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"eyJ0eXAiOiJKV1Q..."}`))
	}))
	defer server.Close()

	azureAccessTokenBaseURL = server.URL
	azureTokenRequestDoer = http.DefaultClient.Do

	resp, err := requestAzureAccessToken(t.Context(), "tenant-123", "client-123", "secret-123", "https://graph.microsoft.com/.default")
	if err != nil {
		t.Fatal(err)
	}

	if resp.AccessToken == "" || resp.TokenType != "Bearer" || resp.ExpiresIn != 3599 || resp.ExtExpiresIn != 3599 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	form, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "client-123" || form.Get("client_secret") != "secret-123" || form.Get("scope") != "https://graph.microsoft.com/.default" {
		t.Fatalf("unexpected form body: %s", gotBody)
	}
}

func TestRequestAzureAccessToken_HTTPError(t *testing.T) {
	t.Helper()

	oldBaseURL := azureAccessTokenBaseURL
	oldDoer := azureTokenRequestDoer
	t.Cleanup(func() {
		azureAccessTokenBaseURL = oldBaseURL
		azureTokenRequestDoer = oldDoer
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`AADSTS70011: invalid scope`))
	}))
	defer server.Close()

	azureAccessTokenBaseURL = server.URL
	azureTokenRequestDoer = http.DefaultClient.Do

	_, err := requestAzureAccessToken(t.Context(), "tenant-123", "client-123", "secret-123", "bad-scope")
	if err == nil || !strings.Contains(err.Error(), "AADSTS70011") {
		t.Fatalf("expected Azure error, got %v", err)
	}
}
