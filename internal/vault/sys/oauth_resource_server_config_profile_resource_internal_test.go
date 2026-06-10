// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// publicKeyObjectType mirrors the element type used for the public_keys list in
// the resource model.
var publicKeyObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		consts.FieldKeyID: types.StringType,
		"pem":             types.StringType,
	},
}

// publicKeysWithOneKey returns a public_keys list containing a single key, which
// is all validateConfiguration inspects (it only checks the element count).
func publicKeysWithOneKey() types.List {
	return types.ListValueMust(publicKeyObjectType, []attr.Value{
		types.ObjectValueMust(publicKeyObjectType.AttrTypes, map[string]attr.Value{
			consts.FieldKeyID: types.StringValue("key-1"),
			"pem":             types.StringValue("-----BEGIN PUBLIC KEY-----"),
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
