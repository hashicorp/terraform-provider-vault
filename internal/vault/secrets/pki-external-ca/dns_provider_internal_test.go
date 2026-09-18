// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// ttlRequestCases covers the common write-side TTL cases for all DNS providers.
var ttlRequestCases = []struct {
	name        string
	ttl         types.Int64
	wantSeconds int64
	wantAbsent  bool
}{
	{
		name:        "sends integer seconds",
		ttl:         types.Int64Value(120),
		wantSeconds: 120,
	},
	{
		name:        "sends zero",
		ttl:         types.Int64Value(0),
		wantSeconds: 0,
	},
	{
		name:       "null TTL omitted from request",
		ttl:        types.Int64Null(),
		wantAbsent: true,
	},
}

// ttlResponseCases covers the common read-side TTL cases for all DNS providers.
var ttlResponseCases = []struct {
	name        string
	ttl         interface{} // value to put in the response map; nil means omit
	wantSeconds int64
	wantNull    bool
	wantErr     string
}{
	{
		name:        "canonical duration string converted to seconds",
		ttl:         "2m0s",
		wantSeconds: 120,
	},
	{
		name:        "non-canonical duration string normalised to seconds",
		ttl:         "120s",
		wantSeconds: 120,
	},
	{
		name:        "minutes-only duration string converted",
		ttl:         "5m",
		wantSeconds: 300,
	},
	{
		name:     "missing TTL leaves field unset",
		ttl:      nil,
		wantNull: true,
	},
	{
		name:    "invalid TTL returns error",
		ttl:     "not-a-duration",
		wantErr: "Cannot parse TTL",
	},
}

func checkTTLRequest(t *testing.T, req map[string]any, wantSeconds int64, wantAbsent bool) {
	t.Helper()
	if wantAbsent {
		if _, present := req[consts.FieldTTL]; present {
			t.Errorf("expected ttl key to be absent for null TTL, but it was present")
		}
		return
	}
	got, ok := req[consts.FieldTTL].(int64)
	if !ok {
		t.Fatalf("expected ttl to be int64, got %T (%v)", req[consts.FieldTTL], req[consts.FieldTTL])
	}
	if got != wantSeconds {
		t.Errorf("ttl = %d, want %d", got, wantSeconds)
	}
}

func checkTTLResponse(t *testing.T, diags interface{ HasError() bool }, detail func() string, gotTTL types.Int64, wantSeconds int64, wantNull bool, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if !diags.HasError() {
			t.Fatalf("expected error containing %q, got none", wantErr)
		}
		if !strings.Contains(detail(), wantErr) {
			t.Fatalf("expected error containing %q, got: %s", wantErr, detail())
		}
		return
	}
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", detail())
	}
	if wantNull {
		if !gotTTL.IsNull() && !gotTTL.IsUnknown() {
			t.Errorf("expected TTL to be null, got %d", gotTTL.ValueInt64())
		}
		return
	}
	if gotTTL.ValueInt64() != wantSeconds {
		t.Errorf("TTL = %d, want %d", gotTTL.ValueInt64(), wantSeconds)
	}
}

// ── AWS Route53 ──────────────────────────────────────────────────────────────

func TestBuildAWSRoute53Request_TTL(t *testing.T) {
	for _, tt := range ttlRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			data := &PKIExternalCADNSProviderAWSRoute53Model{
				TTL:         tt.ttl,
				Identifiers: types.ListValueMust(types.StringType, nil),
			}
			req, diags := buildAWSRoute53Request(context.Background(), data)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			checkTTLRequest(t, req, tt.wantSeconds, tt.wantAbsent)
		})
	}
}

func TestPopulateDataModelFromAPI_AWSRoute53_TTL(t *testing.T) {
	r := &PKIExternalCADNSProviderAWSRoute53Resource{}
	for _, tt := range ttlResponseCases {
		t.Run(tt.name, func(t *testing.T) {
			respData := map[string]interface{}{
				"creation_date":     "2025-01-01T00:00:00Z",
				"last_updated_date": "2025-01-01T00:00:00Z",
				"identifiers":       []interface{}{"example.com"},
			}
			if tt.ttl != nil {
				respData[consts.FieldTTL] = tt.ttl
			}
			var data PKIExternalCADNSProviderAWSRoute53Model
			diags := r.populateDataModelFromAPI(context.Background(), &data, &api.Secret{Data: respData})
			detail := func() string {
				var s []string
				for _, d := range diags {
					s = append(s, d.Detail())
				}
				return strings.Join(s, "; ")
			}
			checkTTLResponse(t, diags, detail, data.TTL, tt.wantSeconds, tt.wantNull, tt.wantErr)
		})
	}
}

// ── Azure ────────────────────────────────────────────────────────────────────

func TestBuildAzureRequest_TTL(t *testing.T) {
	for _, tt := range ttlRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			data := &PKIExternalCADNSProviderAzureModel{
				TTL:         tt.ttl,
				Identifiers: types.ListValueMust(types.StringType, nil),
			}
			req, diags := buildAzureRequest(context.Background(), data)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			checkTTLRequest(t, req, tt.wantSeconds, tt.wantAbsent)
		})
	}
}

func TestPopulateDataModelFromAPI_Azure_TTL(t *testing.T) {
	r := &PKIExternalCADNSProviderAzureResource{}
	for _, tt := range ttlResponseCases {
		t.Run(tt.name, func(t *testing.T) {
			respData := map[string]interface{}{
				"creation_date":     "2025-01-01T00:00:00Z",
				"last_updated_date": "2025-01-01T00:00:00Z",
				"identifiers":       []interface{}{"example.com"},
			}
			if tt.ttl != nil {
				respData[consts.FieldTTL] = tt.ttl
			}
			var data PKIExternalCADNSProviderAzureModel
			diags := r.populateDataModelFromAPI(context.Background(), &data, &api.Secret{Data: respData})
			detail := func() string {
				var s []string
				for _, d := range diags {
					s = append(s, d.Detail())
				}
				return strings.Join(s, "; ")
			}
			checkTTLResponse(t, diags, detail, data.TTL, tt.wantSeconds, tt.wantNull, tt.wantErr)
		})
	}
}

// ── GCP ──────────────────────────────────────────────────────────────────────

func TestBuildGCPRequest_TTL(t *testing.T) {
	for _, tt := range ttlRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			data := &PKIExternalCADNSProviderGCPModel{
				TTL:         tt.ttl,
				Identifiers: types.ListValueMust(types.StringType, nil),
			}
			req, diags := buildGCPRequest(context.Background(), data)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			checkTTLRequest(t, req, tt.wantSeconds, tt.wantAbsent)
		})
	}
}

func TestPopulateDataModelFromAPI_GCP_TTL(t *testing.T) {
	r := &PKIExternalCADNSProviderGCPResource{}
	for _, tt := range ttlResponseCases {
		t.Run(tt.name, func(t *testing.T) {
			respData := map[string]interface{}{
				"creation_date":     "2025-01-01T00:00:00Z",
				"last_updated_date": "2025-01-01T00:00:00Z",
				"identifiers":       []interface{}{"example.com"},
			}
			if tt.ttl != nil {
				respData[consts.FieldTTL] = tt.ttl
			}
			var data PKIExternalCADNSProviderGCPModel
			diags := r.populateDataModelFromAPI(context.Background(), &data, &api.Secret{Data: respData})
			detail := func() string {
				var s []string
				for _, d := range diags {
					s = append(s, d.Detail())
				}
				return strings.Join(s, "; ")
			}
			checkTTLResponse(t, diags, detail, data.TTL, tt.wantSeconds, tt.wantNull, tt.wantErr)
		})
	}
}

// ── RFC2136 ──────────────────────────────────────────────────────────────────

func TestBuildRFC2136Request_TTL(t *testing.T) {
	for _, tt := range ttlRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			data := &PKIExternalCADNSProviderRFC2136Model{
				TTL:         tt.ttl,
				Identifiers: types.ListValueMust(types.StringType, nil),
			}
			req, diags := buildRFC2136Request(context.Background(), data)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			checkTTLRequest(t, req, tt.wantSeconds, tt.wantAbsent)
		})
	}
}

func TestPopulateDataModelFromAPI_RFC2136_TTL(t *testing.T) {
	r := &PKIExternalCADNSProviderRFC2136Resource{}
	for _, tt := range ttlResponseCases {
		t.Run(tt.name, func(t *testing.T) {
			respData := map[string]interface{}{
				"creation_date":     "2025-01-01T00:00:00Z",
				"last_updated_date": "2025-01-01T00:00:00Z",
				"identifiers":       []interface{}{"example.com"},
			}
			if tt.ttl != nil {
				respData[consts.FieldTTL] = tt.ttl
			}
			var data PKIExternalCADNSProviderRFC2136Model
			diags := r.populateDataModelFromAPI(context.Background(), &data, &api.Secret{Data: respData})
			detail := func() string {
				var s []string
				for _, d := range diags {
					s = append(s, d.Detail())
				}
				return strings.Join(s, "; ")
			}
			checkTTLResponse(t, diags, detail, data.TTL, tt.wantSeconds, tt.wantNull, tt.wantErr)
		})
	}
}
