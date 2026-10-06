// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// publicKeyObjectType mirrors the element type used for the public_keys list in
// the resource model.
var publicKeyObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		consts.FieldKeyID: types.StringType,
		consts.FieldPEM:   types.StringType,
	},
}

// publicKeysWithOneKey returns a public_keys list containing a single key, which
// is all validateConfiguration inspects (it only checks the element count).
func publicKeysWithOneKey() types.List {
	return types.ListValueMust(publicKeyObjectType, []attr.Value{
		types.ObjectValueMust(publicKeyObjectType.AttrTypes, map[string]attr.Value{
			consts.FieldKeyID: types.StringValue("key-1"),
			consts.FieldPEM:   types.StringValue("-----BEGIN PUBLIC KEY-----"),
		}),
	})
}

// TestValidateConfiguration exercises the mutual exclusivity rules between the
// JWKS and static PEM configuration modes. These rules are custom provider
// logic with no live Vault dependency, so they are covered here as a unit test.
func TestValidateConfiguration(t *testing.T) {
	tests := []struct {
		name            string
		useJWKS         bool
		jwksURI         types.String
		publicKeys      types.List
		wantErrContains string
	}{
		{
			name:       "jwks mode with jwks_uri is valid",
			useJWKS:    true,
			jwksURI:    types.StringValue("https://example.com/.well-known/jwks.json"),
			publicKeys: types.ListNull(publicKeyObjectType),
		},
		{
			name:       "pem mode with public_keys is valid",
			useJWKS:    false,
			jwksURI:    types.StringNull(),
			publicKeys: publicKeysWithOneKey(),
		},
		{
			name:            "jwks mode without jwks_uri",
			useJWKS:         true,
			jwksURI:         types.StringNull(),
			publicKeys:      types.ListNull(publicKeyObjectType),
			wantErrContains: "jwks_uri is required",
		},
		{
			name:            "pem mode without public_keys",
			useJWKS:         false,
			jwksURI:         types.StringNull(),
			publicKeys:      types.ListNull(publicKeyObjectType),
			wantErrContains: "public_keys is required",
		},
		{
			name:            "jwks mode with public_keys",
			useJWKS:         true,
			jwksURI:         types.StringValue("https://example.com/.well-known/jwks.json"),
			publicKeys:      publicKeysWithOneKey(),
			wantErrContains: "cannot specify both use_jwks=true and public_keys",
		},
		{
			name:            "pem mode with jwks_uri",
			useJWKS:         false,
			jwksURI:         types.StringValue("https://example.com/.well-known/jwks.json"),
			publicKeys:      publicKeysWithOneKey(),
			wantErrContains: "cannot specify both use_jwks=false and jwks_uri",
		},
	}

	r := &OAuthResourceServerConfigProfileResource{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &OAuthResourceServerConfigProfileModel{
				UseJWKS:    types.BoolValue(tt.useJWKS),
				JWKSUri:    tt.jwksURI,
				PublicKeys: tt.publicKeys,
			}

			var diags diag.Diagnostics
			err := r.validateConfiguration(data, &diags)

			switch {
			case tt.wantErrContains == "" && err != nil:
				t.Fatalf("validateConfiguration() unexpected error: %v", err)
			case tt.wantErrContains != "" && err == nil:
				t.Fatalf("validateConfiguration() expected error containing %q, got nil", tt.wantErrContains)
			case tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains):
				t.Fatalf("validateConfiguration() error = %q, want substring %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

// TestAuthorizationDetailsClaimSchemaHasNoVersionIndependentDefault verifies
// that the authorization_details_claim schema attribute has no default value
// and is both optional and computed.
func TestAuthorizationDetailsClaimSchemaHasNoVersionIndependentDefault(t *testing.T) {
	var resp resource.SchemaResponse
	(&OAuthResourceServerConfigProfileResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	attribute, ok := resp.Schema.Attributes[consts.FieldAuthorizationDetailsClaim].(schema.StringAttribute)
	if !ok {
		t.Fatalf("authorization_details_claim schema attribute has type %T, want schema.StringAttribute", resp.Schema.Attributes[consts.FieldAuthorizationDetailsClaim])
	}
	if attribute.Default != nil {
		t.Fatalf("authorization_details_claim has a schema default %v, want no default", attribute.Default)
	}
	if !attribute.Optional || !attribute.Computed {
		t.Fatalf("authorization_details_claim Optional=%t, Computed=%t, want both true", attribute.Optional, attribute.Computed)
	}
}

// TestValidateAuthorizationDetailsClaimVersion verifies the behavior of the
// validateAuthorizationDetailsClaimVersion function for different claim values
// and Vault support scenarios.
func TestValidateAuthorizationDetailsClaimVersion(t *testing.T) {
	tests := []struct {
		name      string
		claim     types.String
		supported bool
		wantErr   bool
	}{
		{
			name:      "unset claim is valid on older Vault",
			claim:     types.StringNull(),
			supported: false,
		},
		{
			name:      "unknown claim is valid on older Vault",
			claim:     types.StringUnknown(),
			supported: false,
		},
		{
			name:      "explicit claim requires newer Vault",
			claim:     types.StringValue("custom_claim"),
			supported: false,
			wantErr:   true,
		},
		{
			name:      "explicit claim is valid on supported Vault",
			claim:     types.StringValue("custom_claim"),
			supported: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthorizationDetailsClaimVersion(tt.claim, tt.supported)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAuthorizationDetailsClaimVersion() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

// TestAuthorizationDetailsClaimState verifies the behavior of the
// authorizationDetailsClaimState function for different current values,
// API values, and Vault support scenarios.
func TestAuthorizationDetailsClaimState(t *testing.T) {
	tests := []struct {
		name      string
		current   types.String
		apiValue  string
		supported bool
		want      types.String
	}{
		{
			name:      "older Vault excludes the claim",
			current:   types.StringNull(),
			supported: false,
			want:      types.StringNull(),
		},
		{
			name:      "supported Vault uses API value",
			current:   types.StringNull(),
			apiValue:  "custom_claim",
			supported: true,
			want:      types.StringValue("custom_claim"),
		},
		{
			name:      "supported Vault fills API default on read or import",
			current:   types.StringUnknown(),
			supported: true,
			want:      types.StringValue(defaultAuthorizationDetailsClaim),
		},
		{
			name:      "preserves the current state value when the API value is empty",
			current:   types.StringValue("custom_claim"),
			supported: true,
			want:      types.StringValue("custom_claim"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorizationDetailsClaimState(tt.current, tt.apiValue, tt.supported)
			if got != tt.want {
				t.Fatalf("authorizationDetailsClaimState() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
