// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestSetToCommaSeparatedString(t *testing.T) {
	ctx := context.Background()

	// Helper to create a types.Set from []string
	makeSet := func(values []string) types.Set {
		set, _ := types.SetValueFrom(ctx, types.StringType, values)
		return set
	}

	tests := []struct {
		name    string
		input   types.Set
		want    string
		wantErr bool
	}{
		{"null-set", types.SetNull(types.StringType), "", false},
		{"unknown-set", types.SetUnknown(types.StringType), "", false},
		{"empty-set", makeSet([]string{}), "", false},
		{"single-element", makeSet([]string{"policy1"}), "policy1", false},
		{"multiple-elements", makeSet([]string{"admin", "dev", "audit"}), "admin,dev,audit", false},
		{"elements-with-special-chars", makeSet([]string{"policy-1", "policy_2"}), "policy-1,policy_2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := SetToCommaSeparatedString(ctx, tt.input)

			if tt.wantErr != diags.HasError() {
				t.Errorf("SetToCommaSeparatedString() wantErr=%v, gotErr=%v, diags=%v", tt.wantErr, diags.HasError(), diags)
			}

			// For multiple elements, compare using maps since Set order is not guaranteed
			if tt.name == "multiple-elements" || tt.name == "elements-with-special-chars" {
				gotParts := strings.Split(got, ",")
				wantParts := strings.Split(tt.want, ",")

				gotSet := make(map[string]bool)
				for _, g := range gotParts {
					gotSet[g] = true
				}
				wantSet := make(map[string]bool)
				for _, w := range wantParts {
					wantSet[w] = true
				}

				if !reflect.DeepEqual(gotSet, wantSet) {
					t.Errorf("SetToCommaSeparatedString() = %q, want %q", got, tt.want)
				}
			} else {
				if got != tt.want {
					t.Errorf("SetToCommaSeparatedString() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestStringSliceToSet(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		input    []string
		wantNull bool
		wantLen  int
		wantErr  bool
	}{
		{"nil-slice", nil, true, 0, false},
		{"empty-slice", []string{}, true, 0, false},
		{"single-element", []string{"policy1"}, false, 1, false},
		{"multiple-elements", []string{"admin", "dev", "audit"}, false, 3, false},
		{"duplicate-elements", []string{"policy1", "policy1", "policy2"}, false, 0, true},
		{"elements-with-special-chars", []string{"policy-1", "policy_2", "policy.3"}, false, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := StringSliceToSet(ctx, tt.input)

			if tt.wantErr != diags.HasError() {
				t.Errorf("StringSliceToSet() wantErr=%v, gotErr=%v, diags=%v", tt.wantErr, diags.HasError(), diags)
			}

			if tt.wantErr {
				return
			}

			if tt.wantNull != got.IsNull() {
				t.Errorf("StringSliceToSet() wantNull=%v, gotNull=%v", tt.wantNull, got.IsNull())
			}

			if !tt.wantNull && len(got.Elements()) != tt.wantLen {
				t.Errorf("StringSliceToSet() got %d elements, want %d", len(got.Elements()), tt.wantLen)
			}
		})
	}
}
