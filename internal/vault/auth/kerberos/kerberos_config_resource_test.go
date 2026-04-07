// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const (
	// Mock base64-encoded keytab for testing
	testKeytab = "BQIAAABUAAIADU1ZTE9DQUwuUkVBTE0ABXZhdWx0AAlsb2NhbGhvc3QAAAABaZ11VQIAEgAgHescP6FZQHb+kxWfQZ2M+hHDI2y7J+PllwXaaAdB4rgAAAACAAAARAACAA1NWUxPQ0FMLlJFQUxNAAV2YXVsdAAJbG9jYWxob3N0AAAAAWmddVUCABEAEH7WVnf3yj8yJjS9fkHFfIsAAAAC"
)

// TestAccKerberosAuthBackendConfig_basic tests basic resource creation and import
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
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases),
				),
			},
			{
				ResourceName:                         "vault_kerberos_auth_backend_config.config",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldKeytabWOVersion},
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_update tests updating the configuration and import
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
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName, "false"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases, "false"),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_full(path, serviceAccount2, true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount2),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName, "true"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases, "true"),
				),
			},
			{
				ResourceName:                         "vault_kerberos_auth_backend_config.config",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldKeytabWOVersion},
			},
		},
	})
}

// TestAccKerberosAuthBackendConfig_updateAndReplacement tests keytab updates and path changes
func TestAccKerberosAuthBackendConfig_updateAndReplacement(t *testing.T) {
	path1 := acctest.RandomWithPrefix("kerberos")
	path2 := acctest.RandomWithPrefix("kerberos")
	serviceAccount := "vault/localhost@EXAMPLE.COM"
	newKeytab := "BQIAAABJAAEADU1ZTE9DQUwuUkVBTE0ABXVzZXIxAAAAAWmddVUCABIAIEwYj3TuYhptSAZ2tAu/Jt8WcCJuvQLnToLPTVKzTyr/AAAAAgAAADkAAQANTVlMT0NBTC5SRUFMTQAFdXNlcjEAAAABaZ11VQIAEQAQ2gqjbGiRd5/K3dj5Wn7Z5QAAAAI="

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path1, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path1),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_keytabUpdate(path1, serviceAccount, newKeytab),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path1),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
				),
			},
			{
				Config: testAccKerberosAuthBackendConfigConfig_basic(path2, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldMount, path2),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldServiceAccount, serviceAccount),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
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
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID missing /config suffix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "auth/kerberos",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID missing auth/ prefix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "kerberos/config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID with empty path between prefix and suffix
			{
				Config:            testAccKerberosAuthBackendConfigConfig_basic("test", "vault/localhost@EXAMPLE.COM"),
				ResourceName:      "vault_kerberos_auth_backend_config.config",
				ImportState:       true,
				ImportStateId:     "auth//config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
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
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldKeytabWO),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldRemoveInstanceName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_config.config", consts.FieldAddGroupAliases),
				),
			},
			{
				PreConfig: func() {
					// Set the namespace environment variable for import
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
				ResourceName:                         "vault_kerberos_auth_backend_config.config",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldKeytabWOVersion},
			},
			{
				// Cleanup step needed for the import step above
				Config: testAccKerberosAuthBackendConfigConfig_namespace(namespace, path, serviceAccount),
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				PlanOnly: true,
			},
		},
	})
}

func testAccKerberosAuthBackendConfigConfig_emptyServiceAccount(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = %q
  keytab_wo_version = 1
  service_account   = ""
}
`, path, testKeytab)
}

func testAccKerberosAuthBackendConfigConfig_emptyKeytab(path, serviceAccount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = ""
  keytab_wo_version = 1
  service_account   = %q
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
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = %q
  keytab_wo_version = 1
  service_account   = %q
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
  keytab_wo            = %q
  keytab_wo_version    = 1
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
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = %q
  keytab_wo_version = 2
  service_account   = %q
}
`, path, keytab, serviceAccount)
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
  namespace         = vault_namespace.test.path
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = %q
  keytab_wo_version = 1
  service_account   = %q
}
`, namespace, path, testKeytab, serviceAccount)
}
