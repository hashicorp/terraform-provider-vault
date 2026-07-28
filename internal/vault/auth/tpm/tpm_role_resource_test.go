// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"context"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestTPMAuthRoleResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaReq := fwresource.SchemaRequest{}
	schemaResp := &fwresource.SchemaResponse{}

	NewTPMAuthRoleResource().Schema(ctx, schemaReq, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %+v", schemaResp.Diagnostics)
	}

	if diags := schemaResp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation diagnostics: %+v", diags)
	}
}

func TestExtractTPMRoleIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		importID  string
		wantErr   bool
		wantMount string
		wantRole  string
	}{
		{
			name:      "valid import id",
			importID:  "auth/tpm/role/my-role",
			wantMount: "tpm",
			wantRole:  "my-role",
		},
		{
			name:      "valid import id with custom mount",
			importID:  "auth/my-tpm-mount/role/role-1",
			wantMount: "my-tpm-mount",
			wantRole:  "role-1",
		},
		{
			name:     "invalid empty id",
			importID: "",
			wantErr:  true,
		},
		{
			name:     "invalid format",
			importID: "auth/tpm/tpmrole/my-role",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotRole, err := extractTPMRoleIdentifiers(tt.importID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for import id %q", tt.importID)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for import id %q: %v", tt.importID, err)
			}
			if gotMount != tt.wantMount {
				t.Fatalf("mount mismatch: got %q, want %q", gotMount, tt.wantMount)
			}
			if gotRole != tt.wantRole {
				t.Fatalf("role mismatch: got %q, want %q", gotRole, tt.wantRole)
			}
		})
	}
}
