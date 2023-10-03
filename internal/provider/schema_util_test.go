// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestSecretsAuthDisableRemountUpgradeV0(t *testing.T) {
	tests := []struct {
		name     string
		rawState map[string]interface{}
		want     map[string]interface{}
		wantErr  bool
	}{
		{
			name: "basic",
			rawState: map[string]interface{}{
				consts.FieldDisableRemount: nil,
			},
			want: map[string]interface{}{
				consts.FieldDisableRemount: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SecretsAuthMountDisableRemountUpgradeV0(nil, tt.rawState, nil)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("SecretsAuthMountDisableRemountUpgradeV0() error = %#v, wantErr %#v", err, tt.wantErr)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SecretsAuthMountDisableRemountUpgradeV0() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}
