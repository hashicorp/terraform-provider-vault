// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func Test_assertVaultState(t *testing.T) {
	resourceName := "resource.test"
	tests := []struct {
		name    string
		resp    *api.Secret
		tfs     *terraform.State
		path    string
		tests   []*VaultStateTest
		wantErr bool
	}{
		{
			name: "string",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": "value1",
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1": "value1",
									},
								},
							},
						},
					},
				},
			},
			path: "string",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
				},
			},
			wantErr: false,
		},
		{
			name: "bool",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": true,
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1": "true",
									},
								},
							},
						},
					},
				},
			},
			path: "bool",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
				},
			},
			wantErr: false,
		},
		{
			name: "slice-ordered",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": []interface{}{
						"val1",
						"val2",
					},
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1.#": "2",
										"attr1.0": "val1",
										"attr1.1": "val2",
									},
								},
							},
						},
					},
				},
			},
			path: "slice-ordered",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
				},
			},
			wantErr: false,
		},
		{
			name: "slice-set-cmp",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": []interface{}{
						"val1",
						"val2",
						"val3",
					},
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1.#": "3",
										"attr1.0": "val2",
										"attr1.1": "val1",
										"attr1.2": "val3",
									},
								},
							},
						},
					},
				},
			},
			path: "slice-set-cmp",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
					AsSet:        true,
				},
			},
			wantErr: false,
		},
		{
			name: "slice-subset-cmp",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": []interface{}{
						"val1",
						"val2",
						"val3",
					},
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1.#": "1",
										"attr1.1": "val1",
									},
								},
							},
						},
					},
				},
			},
			path: "slice-set-cmp",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
					IsSubset:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "slice-superset-error",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"attr1": []interface{}{
						"val1",
					},
				},
			},
			tfs: &terraform.State{
				Version: 0,
				Modules: []*terraform.ModuleState{
					{
						Path: []string{"root"},
						Resources: map[string]*terraform.ResourceState{
							resourceName: {
								Type:         "",
								Dependencies: nil,
								Primary: &terraform.InstanceState{
									ID: "",
									Attributes: map[string]string{
										"attr1.#": "3",
										"attr1.1": "val1",
										"attr1.2": "val2",
										"attr1.3": "val3",
									},
								},
							},
						},
					},
				},
			},
			path: "slice-set-cmp",
			tests: []*VaultStateTest{
				{
					ResourceName: resourceName,
					StateAttr:    "attr1",
					VaultAttr:    "attr1",
					IsSubset:     true,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		// tfs := terraform.NewState()
		// tfs.Modules = tt.tfs.Modules
		t.Run(tt.name, func(t *testing.T) {
			if err := assertVaultState(tt.resp, tt.tfs, tt.path, tt.tests...); (err != nil) != tt.wantErr {
				t.Errorf("assertVaultState() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetGHOrgResponse(t *testing.T) {
	tests := []struct {
		name string
		org  string
		want *GHOrgResponse
	}{
		{
			name: "hashicorp",
			org:  "hashicorp",
			want: &GHOrgResponse{
				Login: "hashicorp",
				ID:    761456,
			},
		},
		{
			name: "github",
			org:  "github",
			want: &GHOrgResponse{
				Login: "github",
				ID:    9919,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetGHOrgResponse(t, tt.org); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetGHOrgResponse() = %v, want %v", got, tt.want)
			}
			v, ok := ghOrgResponseCache.Load(tt.org)
			if !ok {
				t.Fatalf("GetGHOrgResponse() result not cached for %s", tt.org)
			}

			got := v.(*GHOrgResponse)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetGHOrgResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
