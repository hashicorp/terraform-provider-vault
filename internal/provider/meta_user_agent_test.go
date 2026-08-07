// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	providerversion "github.com/hashicorp/terraform-provider-vault/version"
)

// userAgentRecorder captures the User-Agent of every request the provider's
// client makes, and serves the minimum needed for setClient() to succeed.
type userAgentRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (u *userAgentRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.UserAgent())
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":        "test-token",
					"policies":  []string{"default"},
					"ttl":       3600,
					"renewable": true,
				},
			})
		case "/v1/auth/token/create":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-child-token",
					"policies":       []string{"default"},
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		}
	})
}

// observed returns the distinct User-Agent values seen, so a test can assert
// that every request carried the same one.
func (u *userAgentRecorder) observed() []string {
	u.mu.Lock()
	defer u.mu.Unlock()

	var distinct []string
	seen := map[string]bool{}
	for _, ua := range u.seen {
		if !seen[ua] {
			seen[ua] = true
			distinct = append(distinct, ua)
		}
	}

	return distinct
}

func TestProviderMeta_userAgentHeader(t *testing.T) {
	tests := []struct {
		name         string
		appendEnv    string
		vaultHeaders string
		configHeader [2]string
		assertUA     func(t *testing.T, ua string)
	}{
		{
			name: "default",
			assertUA: func(t *testing.T, ua string) {
				wantProduct := providerversion.ProviderName + "/" + providerversion.ProviderVersion()
				if !strings.Contains(ua, wantProduct) {
					t.Errorf("User-Agent %q does not contain %q", ua, wantProduct)
				}
				if !strings.HasPrefix(ua, "Terraform/") {
					t.Errorf("User-Agent %q does not start with Terraform/", ua)
				}
				if !strings.Contains(ua, "Terraform-Plugin-SDK/") {
					t.Errorf("User-Agent %q does not contain the SDK version", ua)
				}
			},
		},
		{
			name:      "TF_APPEND_USER_AGENT is appended",
			appendEnv: "my-wrapper/9.9.9",
			assertUA: func(t *testing.T, ua string) {
				if !strings.Contains(ua, providerversion.ProviderName+"/") {
					t.Errorf("User-Agent %q lost the standard product token", ua)
				}
				if !strings.HasSuffix(ua, "my-wrapper/9.9.9") {
					t.Errorf("User-Agent %q does not end with the appended value", ua)
				}
			},
		},
		{
			name:         "headers block overrides the default",
			configHeader: [2]string{"User-Agent", "from-config/1.0"},
			assertUA: func(t *testing.T, ua string) {
				if ua != "from-config/1.0" {
					t.Errorf("User-Agent = %q, want %q", ua, "from-config/1.0")
				}
			},
		},
		{
			name:         "VAULT_HEADERS overrides the default",
			vaultHeaders: `{"User-Agent":"from-env/1.0"}`,
			assertUA: func(t *testing.T, ua string) {
				if ua != "from-env/1.0" {
					t.Errorf("User-Agent = %q, want %q", ua, "from-env/1.0")
				}
			},
		},
		{
			name:      "explicit override still wins with TF_APPEND_USER_AGENT set",
			appendEnv: "my-wrapper/9.9.9",
			// an operator that pins the User-Agent should get exactly that
			configHeader: [2]string{"User-Agent", "from-config/1.0"},
			assertUA: func(t *testing.T, ua string) {
				if ua != "from-config/1.0" {
					t.Errorf("User-Agent = %q, want %q", ua, "from-config/1.0")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.appendEnv != "" {
				t.Setenv("TF_APPEND_USER_AGENT", tt.appendEnv)
			}
			if tt.vaultHeaders != "" {
				t.Setenv("VAULT_HEADERS", tt.vaultHeaders)
			}

			rec := &userAgentRecorder{}
			config, ln := testutil.TestHTTPServer(t, rec.handler())
			defer ln.Close()

			s := map[string]*schema.Schema{
				consts.FieldAddress: {Type: schema.TypeString, Required: true},
				consts.FieldToken:   {Type: schema.TypeString, Required: true},
				"headers": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name":  {Type: schema.TypeString, Required: true},
							"value": {Type: schema.TypeString, Required: true},
						},
					},
				},
			}
			raw := map[string]interface{}{
				consts.FieldAddress: config.Address,
				consts.FieldToken:   "test-token",
			}
			if tt.configHeader[0] != "" {
				raw["headers"] = []interface{}{
					map[string]interface{}{"name": tt.configHeader[0], "value": tt.configHeader[1]},
				}
			}

			meta, err := NewProviderMeta(schema.TestResourceDataRaw(t, s, raw))
			if err != nil {
				t.Fatalf("NewProviderMeta() error = %v", err)
			}

			if _, err := meta.(*ProviderMeta).GetClient(); err != nil {
				t.Fatalf("GetClient() error = %v", err)
			}

			observed := rec.observed()
			if len(observed) == 0 {
				t.Fatal("no requests were made, cannot assert on the User-Agent")
			}
			if len(observed) > 1 {
				t.Fatalf("requests carried differing User-Agents: %q", observed)
			}

			tt.assertUA(t, observed[0])
		})
	}
}

func TestProviderMeta_getUserAgent(t *testing.T) {
	t.Run("uses the value set during configuration", func(t *testing.T) {
		p := &ProviderMeta{userAgent: "Terraform/1.2.3 terraform-provider-vault/9.9.9"}
		if got := p.getUserAgent(); got != p.userAgent {
			t.Errorf("getUserAgent() = %q, want %q", got, p.userAgent)
		}
	})

	t.Run("falls back when constructed directly", func(t *testing.T) {
		p := &ProviderMeta{}
		got := p.getUserAgent()

		wantProduct := providerversion.ProviderName + "/" + providerversion.ProviderVersion()
		if !strings.Contains(got, wantProduct) {
			t.Errorf("getUserAgent() = %q, does not contain %q", got, wantProduct)
		}
	})

	t.Run("fallback still honors TF_APPEND_USER_AGENT", func(t *testing.T) {
		t.Setenv("TF_APPEND_USER_AGENT", "my-wrapper/9.9.9")

		p := &ProviderMeta{}
		if got := p.getUserAgent(); !strings.HasSuffix(got, "my-wrapper/9.9.9") {
			t.Errorf("getUserAgent() = %q, want suffix %q", got, "my-wrapper/9.9.9")
		}
	})
}

func TestProviderVersion(t *testing.T) {
	// the embedded VERSION file must not carry surrounding whitespace, since it
	// is emitted verbatim into a header
	got := providerversion.ProviderVersion()
	if got == "" {
		t.Fatal("ProviderVersion() is empty")
	}
	if got != strings.TrimSpace(got) {
		t.Errorf("ProviderVersion() = %q, has surrounding whitespace", got)
	}
}
