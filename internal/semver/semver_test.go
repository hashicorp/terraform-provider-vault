package semver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

		data := map[string]interface{}{}
		data[consts.FieldVersion] = t.version

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
	}{
		{
			"server-greater-than",
			"1.8.0",
			true,
			&testSemanticVersionHandler{
				version: "1.11.0",
			},
			false,
		},
		{
			"server-less-than",
			"1.12.0",
			false,
			&testSemanticVersionHandler{
				version: "1.11.0+ent",
			},
			false,
		},
		{
			"server-equal",
			"1.10.0",
			true,
			&testSemanticVersionHandler{
				version: "1.10.0",
			},
			false,
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
				t.Errorf("GreaterThanOrEqual() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if isTFVersionGreater != tt.expected {
				t.Errorf("GreaterThanOrEqual() got = %v, want %v", isTFVersionGreater, tt.expected)
			}
		})
	}
}
