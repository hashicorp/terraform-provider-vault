// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"reflect"
	"strings"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestActivationFlagsResourceMetadata(t *testing.T) {
	t.Parallel()

	resp := &fwresource.MetadataResponse{}
	NewActivationFlagsResource().Metadata(context.Background(), fwresource.MetadataRequest{ProviderTypeName: "vault"}, resp)

	if resp.TypeName != "vault_activation_flags" {
		t.Fatalf("got type name %q, want %q", resp.TypeName, "vault_activation_flags")
	}
}

func TestActivationFlagsResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resp := &fwresource.SchemaResponse{}
	NewActivationFlagsResource().Schema(ctx, fwresource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %+v", resp.Diagnostics)
	}

	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation diagnostics: %+v", diags)
	}

	if _, ok := resp.Schema.Attributes[consts.FieldActivatedFlags]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldActivatedFlags)
	}
	if _, ok := resp.Schema.Attributes[consts.FieldID]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldID)
	}
	if _, ok := resp.Schema.Attributes[consts.FieldNamespace]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldNamespace)
	}
}

func TestRawActivationFlagsToStrings(t *testing.T) {
	tests := []struct {
		name    string
		raw     interface{}
		want    []string
		wantErr bool
	}{
		{
			name: "nil",
			raw:  nil,
			want: []string{},
		},
		{
			name: "string slice",
			raw:  []string{"feature-a", "feature-b"},
			want: []string{"feature-a", "feature-b"},
		},
		{
			name: "interface slice",
			raw:  []interface{}{"feature-a", "feature-b"},
			want: []string{"feature-a", "feature-b"},
		},
		{
			name:    "interface slice with non-string",
			raw:     []interface{}{"feature-a", 1},
			wantErr: true,
		},
		{
			name:    "unexpected type",
			raw:     "feature-a",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rawActivationFlagsToStrings(tt.raw, "activated_flags")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDiffActivationFlags(t *testing.T) {
	tests := []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "returns missing items from right",
			left:  []string{"feature-a", "feature-b"},
			right: []string{"feature-b"},
			want:  []string{"feature-a"},
		},
		{
			name:  "deduplicates left side",
			left:  []string{"feature-a", "feature-a", "feature-b"},
			right: []string{"feature-b"},
			want:  []string{"feature-a"},
		},
		{
			name:  "empty when all are declared",
			left:  []string{"feature-a"},
			right: []string{"feature-a", "feature-b"},
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffActivationFlags(tt.left, tt.right)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestValidateDesiredActivationFlags(t *testing.T) {
	tests := []struct {
		name       string
		desired    []string
		flagsState *activationFlagsState
		wantErr    string
	}{
		{
			name:    "accepts exact feature key",
			desired: []string{"secrets-sync"},
			flagsState: &activationFlagsState{
				Unactivated: []string{"secrets-sync"},
			},
		},
		{
			name:    "suggests hyphenated feature key",
			desired: []string{"secrets_sync"},
			flagsState: &activationFlagsState{
				Unactivated: []string{"secrets-sync"},
			},
			wantErr: `Did you mean "secrets-sync"?`,
		},
		{
			name:    "rejects unknown feature key",
			desired: []string{"unknown-feature"},
			flagsState: &activationFlagsState{
				Unactivated: []string{"secrets-sync"},
			},
			wantErr: `activation flag "unknown-feature" was not returned`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDesiredActivationFlags(tt.desired, tt.flagsState)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestGetActivationFlagsFromResponse_UsesVaultAPIFieldNames(t *testing.T) {
	resp := map[string]interface{}{
		"activated":   []interface{}{"feature-a"},
		"unactivated": []interface{}{"feature-b"},
	}

	activated, err := getActivationFlagsFromResponse(resp, activationFlagsAPIActivatedField)
	if err != nil {
		t.Fatalf("unexpected activated error: %v", err)
	}

	unactivated, err := getActivationFlagsFromResponse(resp, activationFlagsAPIUnactivatedField)
	if err != nil {
		t.Fatalf("unexpected unactivated error: %v", err)
	}

	if !reflect.DeepEqual(activated, []string{"feature-a"}) {
		t.Fatalf("got activated %#v, want %#v", activated, []string{"feature-a"})
	}

	if !reflect.DeepEqual(unactivated, []string{"feature-b"}) {
		t.Fatalf("got unactivated %#v, want %#v", unactivated, []string{"feature-b"})
	}
}
