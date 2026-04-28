// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAliCloudSecretBackend_lifecycle tests create, update, and import for the backend resource.
func TestAliCloudSecretBackend_lifecycle(t *testing.T) {
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
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
				),
			},
			{
				// Update access_key
				// Both access_key and secret_key are sent to Vault (API requires both)
				Config: testAliCloudSecretBackend_config(path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        path,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldSecretKeyWO, consts.FieldSecretKeyWOVersion},
			},
		},
	})
}

// TestAliCloudSecretBackend_writeOnly tests write-only credential pattern with version field
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
				Config: testAliCloudSecretBackend_configWithVersion(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
					// secret_key_wo is write-only, not in state after Read
				),
			},
			{
				// Update secret_key_wo by incrementing version
				Config: testAliCloudSecretBackend_configWithVersion(path, accessKey, updatedSecretKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
					// secret_key_wo is write-only, not in state after Read
				),
			},
			{
				// Keep same secret_key_wo value and version (no update)
				Config: testAliCloudSecretBackend_configWithVersion(path, accessKey, updatedSecretKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
					// secret_key_wo is write-only, not in state after Read
				),
			},
			{
				// Revert secret_key_wo back to original value by incrementing version
				Config: testAliCloudSecretBackend_configWithVersion(path, accessKey, secretKey, 3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "3"),
					// secret_key_wo is write-only, not in state after Read
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_remount tests changing the mount path
// Verifies that changing the mount triggers destroy+recreate
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
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
				),
			},
			{
				Config: testAliCloudSecretBackend_config(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, updatedPath),
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
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
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

// TestAliCloudSecretBackend_namespaceLifecycle tests create and update in a custom namespace.
func TestAliCloudSecretBackend_namespaceLifecycle(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	namespacePath := acctest.RandomWithPrefix("test-namespace")
	accessKey, secretKey := getTestAliCloudCreds(t)
	updatedAccessKey := accessKey + "-updated"

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
				),
			},
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
				),
			},
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_validation groups single-step backend validation tests.
func TestAliCloudSecretBackend_validation(t *testing.T) {
	accessKey, secretKey := getTestAliCloudCreds(t)

	testCases := []struct {
		name        string
		config      string
		expectError string
	}{
		{
			name:        "missing_mount",
			config:      testAliCloudSecretBackend_missingMountConfig(accessKey, secretKey),
			expectError: `The argument "mount" is required`,
		},
		{
			name:        "missing_access_key",
			config:      testAliCloudSecretBackend_missingAccessKeyConfig(acctest.RandomWithPrefix("tf-test-alicloud"), secretKey),
			expectError: `The argument "access_key" is required`,
		},
		{
			name:        "missing_secret_key",
			config:      testAliCloudSecretBackend_missingSecretKeyConfig(acctest.RandomWithPrefix("tf-test-alicloud"), accessKey),
			expectError: `The argument "secret_key_wo" is required`,
		},
		{
			name:        "empty_mount",
			config:      testAliCloudSecretBackend_config("", accessKey, secretKey),
			expectError: `Unable to Create Resource|unsupported operation|path cannot be empty`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: regexp.MustCompile(tc.expectError),
					},
				},
			})
		})
	}
}

// TestAliCloudSecretBackend_defaultNamespace tests backend creation without explicit namespace (uses root)
func TestAliCloudSecretBackend_defaultNamespace(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// When namespace is not specified, it should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldNamespace),
				),
			},
		},
	})
}

func testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "test" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  namespace             = vault_namespace.test.path
  mount                 = vault_mount.test.path
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = 1
}
`, namespacePath, path, accessKey, secretKey)
}

// getTestAliCloudCreds retrieves AliCloud credentials from environment variables
func getTestAliCloudCreds(t *testing.T) (string, string) {
	t.Helper()
	v := testutil.SkipTestEnvUnset(t, "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY")
	return v[0], v[1]
}

// testAliCloudSecretBackend_config returns test configuration for the AliCloud secret backend
func testAliCloudSecretBackend_config(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount                 = vault_mount.test.path
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = 1
}
`, path, accessKey, secretKey)
}

// testAliCloudSecretBackend_configWithVersion returns test configuration with version field
func testAliCloudSecretBackend_configWithVersion(path, accessKey, secretKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount                  = vault_mount.test.path
  access_key             = %q
  secret_key_wo          = %q
  secret_key_wo_version  = %d
}
`, path, accessKey, secretKey, version)
}

// testAliCloudSecretBackend_missingMountConfig returns config without mount field
func testAliCloudSecretBackend_missingMountConfig(accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "alicloud-test"
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = 1
}
`, accessKey, secretKey)
}

// testAliCloudSecretBackend_missingAccessKeyConfig returns config without access_key field
func testAliCloudSecretBackend_missingAccessKeyConfig(path, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount                 = vault_mount.test.path
  secret_key_wo         = %q
  secret_key_wo_version = 1
}
`, path, secretKey)
}

// testAliCloudSecretBackend_missingSecretKeyConfig returns config without secret_key_wo field
func testAliCloudSecretBackend_missingSecretKeyConfig(path, accessKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount      = vault_mount.test.path
  access_key = %q
}
`, path, accessKey)
}
