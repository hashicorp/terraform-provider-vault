// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func TestGetConnectionDetailsFromResponse_mixedValueTypes(t *testing.T) {
	empty := schema.TestResourceDataRaw(t, map[string]*schema.Schema{}, map[string]interface{}{})

	tests := []struct {
		name    string
		details map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name: "vault 2 duration string lifetime",
			details: map[string]interface{}{
				"max_open_connections":    json.Number("5"),
				"max_idle_connections":    json.Number("2"),
				"max_connection_lifetime": "0s",
			},
			want: map[string]interface{}{
				"max_open_connections":    int64(5),
				"max_idle_connections":    int64(2),
				"max_connection_lifetime": float64(0),
			},
		},
		{
			name: "string connection limits",
			details: map[string]interface{}{
				"max_open_connections":    "5",
				"max_idle_connections":    "2",
				"max_connection_lifetime": "30s",
			},
			want: map[string]interface{}{
				"max_open_connections":    int64(5),
				"max_idle_connections":    int64(2),
				"max_connection_lifetime": float64(30),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &api.Secret{
				Data: map[string]interface{}{
					"connection_details": tt.details,
				},
			}

			got := getConnectionDetailsFromResponse(empty, "postgresql.0.", resp)
			if got == nil {
				t.Fatal("expected connection details, got nil")
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Fatalf("%s: got %#v, want %#v", key, got[key], want)
				}
			}
		})
	}
}
