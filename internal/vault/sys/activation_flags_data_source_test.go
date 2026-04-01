// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"reflect"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestActivationFlagsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	resp := &fwdatasource.MetadataResponse{}
	NewActivationFlagsDataSource().Metadata(context.Background(), fwdatasource.MetadataRequest{ProviderTypeName: "vault"}, resp)

	if resp.TypeName != "vault_activation_flags" {
		t.Fatalf("got type name %q, want %q", resp.TypeName, "vault_activation_flags")
	}
}

func TestActivationFlagsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resp := &fwdatasource.SchemaResponse{}
	NewActivationFlagsDataSource().Schema(ctx, fwdatasource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %+v", resp.Diagnostics)
	}

	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation diagnostics: %+v", diags)
	}

	if _, ok := resp.Schema.Attributes[consts.FieldActivatedFlags]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldActivatedFlags)
	}
	if _, ok := resp.Schema.Attributes[consts.FieldUnactivatedFlags]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldUnactivatedFlags)
	}
	if _, ok := resp.Schema.Attributes[consts.FieldID]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldID)
	}
	if _, ok := resp.Schema.Attributes[consts.FieldNamespace]; !ok {
		t.Fatalf("missing %q attribute", consts.FieldNamespace)
	}
}

func TestPopulateActivationFlagsDataSourceModel(t *testing.T) {
	tests := []struct {
		name            string
		vaultData       map[string]interface{}
		wantActivated   []string
		wantUnactivated []string
		wantID          string
		wantError       bool
	}{
		{
			name: "populated lists",
			vaultData: map[string]interface{}{
				activationFlagsAPIActivatedField:   []interface{}{"feature-a"},
				activationFlagsAPIUnactivatedField: []interface{}{"feature-b"},
			},
			wantActivated:   []string{"feature-a"},
			wantUnactivated: []string{"feature-b"},
			wantID:          activationFlagsPath,
		},
		{
			name:            "missing fields become empty lists",
			vaultData:       map[string]interface{}{},
			wantActivated:   []string{},
			wantUnactivated: []string{},
			wantID:          activationFlagsPath,
		},
		{
			name: "malformed activated field",
			vaultData: map[string]interface{}{
				activationFlagsAPIActivatedField: "feature-a",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var model ActivationFlagsDataSourceModel
			diags := populateActivationFlagsDataSourceModel(context.Background(), &model, tt.vaultData)
			if tt.wantError {
				if !diags.HasError() {
					t.Fatal("expected diagnostics error, got none")
				}
				return
			}

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %+v", diags)
			}

			assertListValueEquals(t, model.ActivatedFlags, tt.wantActivated)
			assertListValueEquals(t, model.UnactivatedFlags, tt.wantUnactivated)

			if got := model.ID.ValueString(); got != tt.wantID {
				t.Fatalf("got id %q, want %q", got, tt.wantID)
			}
		})
	}
}

func assertListValueEquals(t *testing.T, value types.List, want []string) {
	t.Helper()

	var got []string
	if diags := value.ElementsAs(context.Background(), &got, false); diags.HasError() {
		t.Fatalf("unexpected list diagnostics: %+v", diags)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
