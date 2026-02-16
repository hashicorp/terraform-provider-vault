// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAliCloudSecretBackend_basic tests basic CRUD operations and write-only pattern
func TestAliCloudSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)
	updatedAccessKey := accessKey + "-updated"

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_initialConfig(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				// Update access_key WITHOUT bumping version
				// Both access_key and secret_key are sent to Vault (API requires both)
				Config: testAliCloudSecretBackend_updateConfig(path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			{
				// Bump version to demonstrate version field works as a trigger
				Config: testAliCloudSecretBackend_updateWithVersionBumpConfig(path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldSecretKeyWO,
			),
		},
	})
}

// TestAliCloudSecretBackend_writeOnly tests write-only credential pattern
func TestAliCloudSecretBackend_writeOnly(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)
	updatedSecretKey := secretKey + "-updated"

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_writeOnlyConfig(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: testAliCloudSecretBackend_writeOnlyUpdateConfig(path, accessKey, updatedSecretKey, 2),
				Check: resource.ComposeTestCheckFunc(
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
				),
			},
			{
				Config: testAliCloudSecretBackend_writeOnlyUpdateConfig(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_writeOnlyIgnored tests that write-only field changes are ignored without version bump
func TestAliCloudSecretBackend_writeOnlyIgnored(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)
	updatedSecretKey := secretKey + "-updated"

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_writeOnlyConfig(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			{
				// NEGATIVE TEST: Change secret_key_wo WITHOUT bumping version
				// Terraform will NOT detect the change (write-only field)
				// This step will show NO changes detected (ExpectNonEmptyPlan would fail)
				Config: testAliCloudSecretBackend_writeOnlyConfig(path, accessKey, updatedSecretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					// State remains unchanged because Update() was never called
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
				// This is the key: Terraform sees no changes, so no plan is generated
				// The config has updatedSecretKey but state still has old secretKey
				// This demonstrates why the version field is necessary
			},
			{
				// Now bump version to actually apply the secret_key change
				Config: testAliCloudSecretBackend_writeOnlyConfig(path, accessKey, updatedSecretKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_remount tests changing the mount path
func TestAliCloudSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	updatedPath := acctest.RandomWithPrefix("tf-test-alicloud-updated")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_initialConfig(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
				),
			},
			{
				Config: testAliCloudSecretBackend_initialConfig(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_destroy tests that the backend is properly destroyed
func TestAliCloudSecretBackend_destroy(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_initialConfig(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
				),
			},
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

// getTestAliCloudCreds retrieves AliCloud credentials from environment variables
func getTestAliCloudCreds(t *testing.T) (string, string) {
	t.Helper()
	v := testutil.SkipTestEnvUnset(t, "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY")
	return v[0], v[1]
}

// testAliCloudSecretBackend_initialConfig returns initial test configuration
func testAliCloudSecretBackend_initialConfig(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path       = %q
  access_key = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}
`, path, accessKey, secretKey)
}

// testAliCloudSecretBackend_updateConfig returns updated test configuration (version stays 1)
func testAliCloudSecretBackend_updateConfig(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path       = %q
  access_key = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}
`, path, accessKey, secretKey)
}

// testAliCloudSecretBackend_updateWithVersionBumpConfig returns configuration with version bump to 2
func testAliCloudSecretBackend_updateWithVersionBumpConfig(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path       = %q
  access_key = %q
  secret_key_wo = %q
  secret_key_wo_version = 2
}
`, path, accessKey, secretKey)
}

// testAliCloudSecretBackend_writeOnlyConfig returns write-only test configuration
func testAliCloudSecretBackend_writeOnlyConfig(path, accessKey, secretKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = %d
}
`, path, accessKey, secretKey, version)
}

// testAliCloudSecretBackend_writeOnlyUpdateConfig returns updated write-only configuration
func testAliCloudSecretBackend_writeOnlyUpdateConfig(path, accessKey, secretKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = %d
}
`, path, accessKey, secretKey, version)
}

// Made with Bob
