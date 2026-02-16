// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAliCloudSecretBackend_basic tests basic CRUD operations
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
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				// Update access_key
				// Both access_key and secret_key are sent to Vault (API requires both)
				Config: testAliCloudSecretBackend_config(path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_writeOnly tests write-only credential pattern with multiple updates
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
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				// Update secret_key_wo to new value
				Config: testAliCloudSecretBackend_config(path, accessKey, updatedSecretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				// Keep same secret_key_wo value (updatedSecretKey) - no changes, no API call
				Config: testAliCloudSecretBackend_config(path, accessKey, updatedSecretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				// Revert secret_key_wo back to original value
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, not in state after Read
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				// Keep same secret_key_wo value (original) - no changes, no API call
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_remount tests changing the mount path
// Verifies that changing the path triggers destroy+recreate with a new accessor
func TestAliCloudSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	updatedPath := acctest.RandomWithPrefix("tf-test-alicloud-updated")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	var originalAccessor string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_config(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					// Capture the accessor value
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}
						originalAccessor = rs.Primary.Attributes[consts.FieldAccessor]
						return nil
					},
				),
			},
			{
				Config: testAliCloudSecretBackend_config(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					// Accessor should be different after path change (destroy+recreate = new accessor)
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}
						currentAccessor := rs.Primary.Attributes[consts.FieldAccessor]
						if currentAccessor == originalAccessor {
							return fmt.Errorf("accessor should change after path change, but remained: %s", originalAccessor)
						}
						return nil
					},
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

// TestAliCloudSecretBackend_namespace tests backend creation in a custom namespace
func TestAliCloudSecretBackend_namespace(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	namespacePath := acctest.RandomWithPrefix("test-namespace")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_namespaceCredentialUpdate tests updating credentials in a namespace
func TestAliCloudSecretBackend_namespaceCredentialUpdate(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
				),
			},
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, updatedAccessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, updatedAccessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_namespaceAccessor tests accessor field in namespace
func TestAliCloudSecretBackend_namespaceAccessor(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	namespacePath := acctest.RandomWithPrefix("test-namespace")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespacePath),
					// Verify accessor is set (format: alicloud_<hash>)
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					resource.TestMatchResourceAttr(resourceName, consts.FieldAccessor,
						regexp.MustCompile("^alicloud_[a-f0-9]+$")),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_missingPath tests validation when path is missing
func TestAliCloudSecretBackend_missingPath(t *testing.T) {
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAliCloudSecretBackend_missingPathConfig(accessKey, secretKey),
				ExpectError: regexp.MustCompile(`The argument "path" is required`),
			},
		},
	})
}

// TestAliCloudSecretBackend_missingAccessKey tests validation when access_key is missing
func TestAliCloudSecretBackend_missingAccessKey(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	_, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAliCloudSecretBackend_missingAccessKeyConfig(path, secretKey),
				ExpectError: regexp.MustCompile(`The argument "access_key" is required`),
			},
		},
	})
}

// TestAliCloudSecretBackend_missingSecretKey tests validation when secret_key_wo is missing
func TestAliCloudSecretBackend_missingSecretKey(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, _ := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAliCloudSecretBackend_missingSecretKeyConfig(path, accessKey),
				ExpectError: regexp.MustCompile(`The argument "secret_key_wo" is required`),
			},
		},
	})
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					// When namespace is not specified, it should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldNamespace),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_accessorFormat tests that accessor field has correct format
func TestAliCloudSecretBackend_accessorFormat(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					// Verify accessor matches expected format: alicloud_<hash>
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					resource.TestMatchResourceAttr(resourceName, consts.FieldAccessor,
						regexp.MustCompile("^alicloud_[a-f0-9]+$")),
				),
			},
		},
	})
}

// TestAliCloudSecretBackend_emptyPath tests error when path is empty string
func TestAliCloudSecretBackend_emptyPath(t *testing.T) {
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAliCloudSecretBackend_config("", accessKey, secretKey),
				ExpectError: regexp.MustCompile(`Error mounting AliCloud backend|unsupported operation|path cannot be empty`),
			},
		},
	})
}

func testAliCloudSecretBackend_namespaceConfig(namespacePath, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_alicloud_secret_backend" "test" {
  namespace     = vault_namespace.test.path
  path          = %q
  access_key    = %q
  secret_key_wo = %q
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
resource "vault_alicloud_secret_backend" "test" {
  path          = %q
  access_key    = %q
  secret_key_wo = %q
}
`, path, accessKey, secretKey)
}

// Made with Bob

// testAliCloudSecretBackend_missingPathConfig returns config without path field
func testAliCloudSecretBackend_missingPathConfig(accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  access_key    = %q
  secret_key_wo = %q
}
`, accessKey, secretKey)
}

// testAliCloudSecretBackend_missingAccessKeyConfig returns config without access_key field
func testAliCloudSecretBackend_missingAccessKeyConfig(path, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = %q
  secret_key_wo = %q
}
`, path, secretKey)
}

// testAliCloudSecretBackend_missingSecretKeyConfig returns config without secret_key_wo field
func testAliCloudSecretBackend_missingSecretKeyConfig(path, accessKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path       = %q
  access_key = %q
}
`, path, accessKey)
}
