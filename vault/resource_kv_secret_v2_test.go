// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var testKVV2Data = map[string]interface{}{
	"foo": "bar",
	"baz": "qux",
}

func TestAccKVSecretV2_pathRegex(t *testing.T) {
	tests := map[string]struct {
		path      string
		wantMount string
		wantName  string
	}{
		"no nesting": {
			path:      "kvv2/data/a/b/c/d",
			wantMount: "kvv2",
			wantName:  "a/b/c/d",
		},
		"nested": {
			path:      "kvv2/data/test/b/c/test/d",
			wantMount: "kvv2",
			wantName:  "test/b/c/test/d",
		},
		"nested-with-double-data": {
			path:      "kvv2/data/a/b/c/data/d",
			wantMount: "kvv2",
			wantName:  "a/b/c/data/d",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mount, err := getKVV2SecretMountFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if mount != tc.wantMount {
				t.Fatalf("expected mount %q, got %q", tc.wantMount, mount)
			}

			name, err := getKVV2SecretNameFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if name != tc.wantName {
				t.Fatalf("expected name %q, got %q", tc.wantName, name)
			}
		})
	}
}

func TestAccKVSecretV2(t *testing.T) {
	t.Parallel()
	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

	updatedMount := acctest.RandomWithPrefix("random-prefix/tf-cloud-metadata")
	updatedName := acctest.RandomWithPrefix("tf-database-creds")

	customMetadata := `{"extra":"cheese","pizza":"please"}`

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretV2Config_initial(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "0"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.deletion_time", ""),
					resource.TestCheckResourceAttr(resourceName, "metadata.custom_metadata", "null"),
				),
			},
			{
				Config: testKVSecretV2Config_updated(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.extra", "cheese"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.pizza", "please"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.deletion_time", ""),
					resource.TestCheckResourceAttr(resourceName, "metadata.custom_metadata", customMetadata),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"data_json", "disable_read",
					"delete_all_versions",
				},
			},
			{
				Config: testKVSecretV2Config_initial(updatedMount, updatedName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, updatedMount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, updatedName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", updatedMount, updatedName)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"data_json", "disable_read",
					"delete_all_versions",
				},
			},
		},
	})
}

func TestAccKVSecretV2_DisableRead(t *testing.T) {
	t.Parallel()
	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					mountKVEngine(t, mount, name)
				},
				Config: testKVSecretV2Config_DisableRead(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "disable_read", "true"),
				),
			},
			{
				PreConfig: func() {
					writeKVData(t, mount, name)
				},
				Config: testKVSecretV2Config_DisableRead(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "disable_read", "true"),
				),
			},
			{
				PreConfig: func() {
					readKVData(t, mount, name)
				},
				Config: testKVSecretV2Config_DisableRead(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "disable_read", "true"),
				),
			},
		},
	})
}

// Fadia u have added this
func TestAccKVSecretV2_UpdateOutsideTerraform(t *testing.T) {
	// TODO skipping in CI for now. Determine if this is still a valid test case
	t.Skip()
	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretV2Config_initial(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
				),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					// Simulate external change using Vault CLI
					path := fmt.Sprintf("%s/data/%s", mount, name)
					_, err := client.Logical().Write(path, map[string]interface{}{"data": map[string]interface{}{"testkey3": "testvalue3"}})
					if err != nil {
						t.Fatalf(fmt.Sprintf("error simulating external change; err=%s", err))
					}

				},

				Config: testKVSecretV2Config_initial(mount, name),

				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "data_json", "{\"flag\":false,\"foo\":\"bar\",\"zip\":\"zap\"}"),
					//we check that the provider updated vault to match the the terraform config therefor creating a new version the secret.
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "3"),
				),
			},
		},
	},
	)
}

// TestAccKVSecretV2_data_json_wo ensures write-only attribute
// `data_json_wo` works as expected
func TestAccKVSecretV2_data_json_wo(t *testing.T) {
	t.Parallel()

	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			//  Write-only attributes are only supported in Terraform 1.11 and later.
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testKVSecretV2Config_data_json_wo(mount, name, 1),
				Check: resource.ComposeTestCheckFunc(
					assertKVDataEquals(mount, name, map[string]interface{}{
						"zip": "zoop",
						"foo": "baz",
					}),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDataJSONWOVersion, "1"),
				),
			},
			{
				// Update data
				Config: testKVSecretV2Config_data_json_wo_updated(mount, name, 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					assertKVDataEquals(mount, name, map[string]interface{}{
						"zip": "zap",
						"foo": "bar",
					}),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDataJSONWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDataJSONWO, consts.FieldDataJSONWOVersion,
				consts.FieldDisableRead, consts.FieldDeleteAllVersions),
		},
	})
}

// TestAccKVSecretV2_WriteOnlyMigration confirms migrating from legacy
// non-muxed Provider implementation to new write-only attribute implementation
// works as expected
func TestAccKVSecretV2_WriteOnlyMigration(t *testing.T) {
	t.Parallel()

	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			//  Write-only attributes are only supported in Terraform 1.11 and later.
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"vault": {
						// 4.8.0 is not multiplexed
						VersionConstraint: "4.8.0",
						Source:            "hashicorp/vault",
					},
				},
				Config: testKVSecretV2Config_initial(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					// can still read sensitive data in state
					resource.TestCheckResourceAttr(resourceName, "data.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.flag", "false"),
				),
			},
			// upgrade to new Muxed TFVP with write-only attributes, ensure plan is seamless
			{
				ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
				Config:                   testKVSecretV2Config_initial(mount, name),
				PlanOnly:                 true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					// sensitive data will no longer be set to state
					// data_json is still being used, so it will still be in state
					resource.TestCheckResourceAttr(resourceName, "data.%", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "data_json"),
				),
			},
			// update config to use write-only attributes
			{
				ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
				Config:                   testKVSecretV2Config_data_json_wo(mount, name, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					// sensitive data will no longer be set to state
					// data_json is no longer being used, so it will not be in state
					resource.TestCheckResourceAttr(resourceName, "data.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "data_json", ""),
				),
			},
		},
	})
}

func readKVData(t *testing.T, mount, name string) {
	t.Helper()
	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	// Read data at path
	path := fmt.Sprintf("%s/data/%s", mount, name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		t.Fatalf(fmt.Sprintf("error reading from Vault; err=%s", err))
	}

	if resp == nil {
		t.Fatalf("empty response")
	}
	if len(resp.Data) == 0 {
		t.Fatalf("kvv2 secret data should not be empty")
	}
	if !reflect.DeepEqual(resp.Data["data"], testKVV2Data) {
		t.Fatalf("kvv2 secret data does not match got: %#+v, want: %#+v", resp.Data["data"], testKVV2Data)
	}

}

func assertKVDataEquals(mount, name string, expected map[string]interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		// Read data at path
		path := fmt.Sprintf("%s/data/%s", mount, name)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading from Vault; err=%s", err)
		}

		if resp == nil {
			return fmt.Errorf("empty response")
		}
		if len(resp.Data) == 0 {
			return fmt.Errorf("kvv2 secret data should not be empty")
		}
		if !reflect.DeepEqual(resp.Data["data"], expected) {
			return fmt.Errorf("kvv2 secret data does not match got: %#+v, want: %#+v", resp.Data["data"], expected)
		}
		return nil
	}
}

func writeKVData(t *testing.T, mount, name string) {
	t.Helper()
	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	data := map[string]interface{}{
		consts.FieldData: testKVV2Data,
	}
	// Write data at path
	path := fmt.Sprintf("%s/data/%s", mount, name)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		t.Fatalf(fmt.Sprintf("error writing to Vault; err=%s", err))
	}

	if resp == nil {
		t.Fatalf("empty response")
	}
}

func mountKVEngine(t *testing.T, mount, name string) {
	t.Helper()
	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	err := client.Sys().Mount(mount, &api.MountInput{
		Type:        "kv-v2",
		Description: "Mount for testing KV datasource",
	})
	if err != nil {
		t.Fatalf(fmt.Sprintf("error mounting kvv2 engine; err=%s", err))
	}
}

func testKVSecretV2Config_DisableRead(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount        = "%s"
  name         = "%s"
  disable_read = true
  data_json    = jsonencode({})
}`, mount, name)
}

func testKVSecretV2Config_initial(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  delete_all_versions = true
  data_json = jsonencode(
    {
      zip  = "zap",
      foo  = "bar",
      flag = false
    }
  )
}`, name)

	return ret
}

func testKVSecretV2Config_updated(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  delete_all_versions = true
  data_json = jsonencode(
    {
      zip  = "zoop",
      foo  = "baz",
      flag = false
    }
  )
  custom_metadata {
    max_versions = 5
    data = {
      extra = "cheese",
      pizza = "please"
    }
  }
}`, name)

	return ret
}

func testKVSecretV2Config_data_json_wo(mount, name string, version int) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  data_json_wo = jsonencode(
    {
      zip  = "zoop",
      foo  = "baz",
    }
  )
  data_json_wo_version = %d
}`, name, version)

	return ret
}

func testKVSecretV2Config_data_json_wo_updated(mount, name string, version int) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  data_json_wo = jsonencode(
    {
      zip  = "zap",
      foo  = "bar",
    }
  )
  data_json_wo_version = %d
}`, name, version)

	return ret
}
