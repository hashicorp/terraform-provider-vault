// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/vault/api"
)

const (
	// Mock base64-encoded keytab for testing
	testKeytab = "BQIAAABUAAIADU1ZTE9DQUwuUkVBTE0ABXZhdWx0AAlsb2NhbGhvc3QAAAABaZ11VQIAEgAgHescP6FZQHb+kxWfQZ2M+hHDI2y7J+PllwXaaAdB4rgAAAACAAAARAACAA1NWUxPQ0FMLlJFQUxNAAV2YXVsdAAJbG9jYWxob3N0AAAAAWmddVUCABEAEH7WVnf3yj8yJjS9fkHFfIsAAAAC"
)

// TestAccKerberosAuthBackendConfig_basic tests basic resource creation and update
func TestAccKerberosAuthBackendConfig_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_update tests updating the configuration
func TestAccKerberosAuthBackendConfig_update(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount1 := "vault/localhost@EXAMPLE.COM"
	serviceAccount2 := "vault/newhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_full(path, serviceAccount1, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount1),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName, "false"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases, "false"),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_full(path, serviceAccount2, true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount2),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName, "true"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases, "true"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_keytabUpdate tests updating the keytab
func TestAccKerberosAuthBackendConfig_keytabUpdate(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"
	newKeytab := "BQIAAABJAAEADU1ZTE9DQUwuUkVBTE0ABXVzZXIxAAAAAWmddVUCABIAIEwYj3TuYhptSAZ2tAu/Jt8WcCJuvQLnToLPTVKzTyr/AAAAAgAAADkAAQANTVlMT0NBTC5SRUFMTQAFdXNlcjEAAAABaZ11VQIAEQAQ2gqjbGiRd5/K3dj5Wn7Z5QAAAAI="

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_keytabUpdate(path, serviceAccount, newKeytab),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_import tests importing the resource
func TestAccKerberosAuthBackendConfig_import(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_full(path, serviceAccount, true, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
				),
			},
			{
				ResourceName:                         "vault_kerberos_auth_backend_config.config",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldKeytab, consts.FieldRemoveInstanceName, consts.FieldAddGroupAliases},
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_defaultCheck tests to check default values
func TestAccKerberosAuthBackendConfig_defaultCheck(t *testing.T) {
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_defaultValues(serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, "kerberos"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_pathChange tests that changing path requires replacement
func TestAccKerberosAuthBackendConfig_pathChange(t *testing.T) {
	path1 := acctest.RandomWithPrefix("kerberos")
	path2 := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path1, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path1),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path2, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path2),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_validationErrors tests various validation errors
func TestAccKerberosAuthBackendConfig_validationErrors(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test missing keytab
			{
				Config:      testAccKerberosAuthBackendConfigConfig_missingKeytab(path, serviceAccount),
				ExpectError: regexp.MustCompile(`(attribute|argument) "keytab" is required`),
			},
			// Test missing service account
			{
				Config:      testAccKerberosAuthBackendConfigConfig_missingServiceAccount(path),
				ExpectError: regexp.MustCompile(`(attribute|argument) "service_account" is required`),
			},
			// Test empty service account - empty string passes Terraform validation but fails at Vault API
			{
				Config:      testAccKerberosAuthBackendConfigConfig_emptyServiceAccount(path),
				ExpectError: regexp.MustCompile(`data does not contain service_account|string must not be empty`),
			},
			// Test empty keytab - empty string passes Terraform validation but fails at Vault API
			{
				Config:      testAccKerberosAuthBackendConfigConfig_emptyKeytab(path, serviceAccount),
				ExpectError: regexp.MustCompile(`data does not contain keytab|string must not be empty`),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_runtimeErrors tests runtime errors
func TestAccKerberosAuthBackendConfig_runtimeErrors(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"
	invalidKeytab := "not-valid-base64!@#$"
	nonExistentPath := "non-existent-kerberos-backend"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test invalid keytab content
			{
				Config:      testAccKerberosAuthBackendConfigConfig_invalidKeytab(path, serviceAccount, invalidKeytab),
				ExpectError: regexp.MustCompile(`error writing|invalid|failed`),
			},
			// Test non-existent backend
			{
				Config:      testAccKerberosAuthBackendConfigConfig_nonExistentBackend(nonExistentPath, serviceAccount),
				ExpectError: regexp.MustCompile(`error writing|no handler for route|unsupported path`),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_configNotFound tests the config not found scenario
func TestAccKerberosAuthBackendConfig_configNotFound(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a valid configuration
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
				),
			},
			// Step 2: Test config not found (lines 195-200)
			// Delete the config but keep the backend, then try to refresh
			{
				PreConfig: func() {
					// Get a Vault client and recreate backend without config
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}
					// Disable the auth backend
					if err := client.Sys().DisableAuth(path); err != nil {
						t.Logf("Warning: failed to disable auth mount: %v", err)
					}
					// Re-enable it without configuration
					if err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
						Type: "kerberos",
					}); err != nil {
						t.Fatalf("failed to enable auth mount: %v", err)
					}
				},
				Config:      testAccKerberosAuthBackendConfigConfig_basic(path, serviceAccount),
				ExpectError: regexp.MustCompile(`Kerberos auth backend config not found`),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_importErrors tests import validation errors
func TestAccKerberosAuthBackendConfig_importErrors(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test completely invalid import ID
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "invalid-import-id",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID missing /config suffix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "auth/kerberos",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID missing auth/ prefix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "kerberos/config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID with empty path between prefix and suffix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "auth//config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_namespace tests configuration with namespace (Enterprise only)
// Note: This test is currently skipped as vault_auth_backend resource doesn't properly support
// namespaces in the Plugin Framework. This test serves as documentation for the namespace field.
func TestAccKerberosAuthBackendConfig_namespace(t *testing.T) {

	namespace := acctest.RandomWithPrefix("tf-ns")
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_namespace(namespace, path, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_importWithNamespace tests importing with namespace (Enterprise only)
func TestAccKerberosAuthBackendConfig_importWithNamespace(t *testing.T) {
	namespace := acctest.RandomWithPrefix("tf-ns")
	path := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_namespace(namespace, path, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
				),
			},
			{
				ResourceName:                         "vault_kerberos_auth_backend_config.config",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldKeytab, consts.FieldRemoveInstanceName, consts.FieldAddGroupAliases},
				PreConfig: func() {
					// Set the namespace environment variable for import
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
			},
		},
	})
}

// Configuration templates for negative tests

func testAccKerberosAuthBackendConfigConfig_missingKeytab(path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  service_account = %q
}
`, path, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_missingServiceAccount(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount  = vault_auth_backend.kerberos.path
  keytab = %q
}
`, path, testKeytab)
}

func testAccKerberosAuthBackendConfigConfig_invalidKeytab(path, serviceAccount, keytab string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = %q
  service_account = %q
}
`, path, keytab, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_emptyServiceAccount(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = %q
  service_account = ""
}
`, path, testKeytab)
}

func testAccKerberosAuthBackendConfigConfig_nonExistentBackend(path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_kerberos_auth_backend_config" "config" {
  mount           = %q
  keytab          = %q
  service_account = %q
}
`, path, testKeytab, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_emptyKeytab(path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = ""
  service_account = %q
}
`, path, serviceAccount)
}

// Configuration templates for positive tests

func testAccKerberosAuthBackendConfigConfig_basic(path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = %q
  service_account = %q
}
`, path, testKeytab, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_full(path, serviceAccount string, removeInstanceName, addGroupAliases bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount                = vault_auth_backend.kerberos.path
  keytab               = %q
  service_account      = %q
  remove_instance_name = %t
  add_group_aliases    = %t
}
`, path, testKeytab, serviceAccount, removeInstanceName, addGroupAliases)
}

func testAccKerberosAuthBackendConfigConfig_keytabUpdate(path, serviceAccount, keytab string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = %q
  service_account = %q
}
`, path, keytab, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_defaultValues(serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "config" {
  keytab          = %q
  service_account = %q
  depends_on      = [vault_auth_backend.kerberos]
}
`, testKeytab, serviceAccount)
}

func testAccKerberosAuthBackendConfigConfig_namespace(namespace, path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.test.path
  type      = "kerberos"
  path      = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  namespace       = vault_namespace.test.path
  mount           = vault_auth_backend.kerberos.path
  keytab          = %q
  service_account = %q
}
`, namespace, path, testKeytab, serviceAccount)
}
