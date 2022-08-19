package semver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type testSemanticVersionHandler struct {
	version string
}

func (t *testSemanticVersionHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			consts.FieldVersion: t.version,
		}

		m, err := json.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(m)
	}
}

func TestGreaterThanOrEqual(t *testing.T) {
	testCases := []struct {
		name           string
		minVersion     string
		expected       bool
		versionHandler *testSemanticVersionHandler
		wantErr        bool
		expectedErr    string
	}{
		{
			name:       "server-greater-than",
			minVersion: "1.8.0",
			expected:   true,
			versionHandler: &testSemanticVersionHandler{
				version: "1.11.0",
			},
			wantErr: false,
		},
		{
			name:       "server-less-than",
			minVersion: "1.12.0",
			expected:   false,
			versionHandler: &testSemanticVersionHandler{
				version: "1.11.0+ent",
			},
			wantErr: false,
		},
		{
			name:       "server-equal",
			minVersion: "1.10.0",
			expected:   true,
			versionHandler: &testSemanticVersionHandler{
				version: "1.10.0",
			},
			wantErr: false,
		},
		{
			name:       "invalid-min-version",
			minVersion: "invalid",
			expected:   false,
			versionHandler: &testSemanticVersionHandler{
				version: "1.11.0",
			},
			wantErr:     true,
			expectedErr: "Malformed version",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.versionHandler

			config, ln := testutil.TestHTTPServer(t, r.handler())
			defer ln.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			c, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()

			isTFVersionGreater, _, err := GreaterThanOrEqual(ctx, c, tt.minVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GreaterThanOrEqual() got an error=%s, wantErr %v", err.Error(), tt.wantErr)
				return
			}
			if err != nil && !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("GreaterThanOrEqual() error = %s, expectedErr %s", err.Error(), tt.expectedErr)
			}
			if isTFVersionGreater != tt.expected {
				t.Errorf("GreaterThanOrEqual() got = %v, want %v", isTFVersionGreater, tt.expected)
			}
		})
	}
}
