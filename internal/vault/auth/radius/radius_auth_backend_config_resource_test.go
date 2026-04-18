// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const (
	testRadiusHost        = "127.0.0.1"
	testRadiusSecret      = "testsecret"
	testRadiusSecretV1    = 1
	testRadiusBaseBodyFmt = `
	host      = %q
	secret_wo = %q
	secret_wo_version = %d
`
	testRadiusBaseBodyWithExtraFmt = `
	host      = %q
	secret_wo = %q
	secret_wo_version = %d
%s
`
)

func TestAccRadiusAuthBackendConfig_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("radius")
	resourceType := "vault_radius_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, testRadiusHost),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDialTimeout, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNASPort, "10"),
				),
			},
			{
				Config: testAccRadiusAuthBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "radius.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1813"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDialTimeout, "15"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNASPort, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUnregisteredUserPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldUnregisteredUserPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldUnregisteredUserPolicies+".*", "dev"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "1200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "3000"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldSecretWO, consts.FieldSecretWOVersion},
			},
		},
	})
}

func testAccRadiusAuthBackendMountConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "radius"
	path = "%s"
}
`, path)
}

func testAccRadiusAuthBackendConfig(path, body string) string {
	return fmt.Sprintf(`
%s

resource "vault_radius_auth_backend" "test" {
	mount = vault_auth_backend.test.path
%s
}
`, testAccRadiusAuthBackendMountConfig(path), body)
}

func testAccRadiusAuthBackendConfig_basic(path string) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(testRadiusBaseBodyFmt, testRadiusHost, testRadiusSecret, testRadiusSecretV1))
}

func testAccRadiusAuthBackendConfig_updated(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                       = "radius.example.com"
	port                       = 1813
	secret_wo                  = "testsecret"
	secret_wo_version          = 1
	unregistered_user_policies = ["default", "dev"]
	dial_timeout               = 15
	nas_port                   = 20
	token_ttl                  = 1200
	token_max_ttl              = 3000
`)
}

func testAccRadiusAuthBackendConfig_secretWOUpdation(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host              = "127.0.0.1"
	secret_wo         = "rotatedsecret"
	secret_wo_version = 2
`)
}

// TestAccRadiusAuthBackend_secretWO tests that the write-only secret_wo attribute is not stored in state
func TestAccRadiusAuthBackendConfig_secretWO(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-wo")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, testRadiusHost),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretWOVersion, "1"),
					// Verify write-only secret is not stored in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretWO),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackendConfig_secretWOVersionUpdate tests that write-only
// secret updation is driven by secret_wo_version and that only the version is
// persisted in state.
func TestAccRadiusAuthBackendConfig_secretWOVersionUpdate(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-wo-version")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, testRadiusHost),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretWO),
				),
			},
			{
				Config: testAccRadiusAuthBackendConfig_secretWOUpdation(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, testRadiusHost),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretWO),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_aliasMetadata tests alias_metadata field.
// This test requires Vault Enterprise 1.21+ for alias_metadata support.
func TestAccRadiusAuthBackendConfig_aliasMetadata(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-alias")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test alias_metadata
			{
				Config: testAccRadiusAuthBackendConfig_aliasMetadata(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".%", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".foo", "bar"),
				),
			},
		},
	})
}

// Config helper functions
func testAccRadiusAuthBackendConfig_aliasMetadata(path string) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(testRadiusBaseBodyWithExtraFmt, testRadiusHost, testRadiusSecret, testRadiusSecretV1, `
	alias_metadata = {
		foo = "bar"
	}
`))
}

// TestAccRadiusAuthBackend_namespace tests RADIUS auth backend creation within a namespace.
// This test requires Vault Enterprise as namespaces are an enterprise feature.
func TestAccRadiusAuthBackendConfig_namespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("test-ns")
	path := acctest.RandomWithPrefix("radius-ns")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_namespace(ns, path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, testRadiusHost),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
				),
			},
			{
				// Set namespace via environment variable for import
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldSecretWO, consts.FieldSecretWOVersion},
			},
			{
				// Clean up the environment variable
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				Config:   testAccRadiusAuthBackendConfig_namespace(ns, path),
				PlanOnly: true,
			},
		},
	})
}

// TestAccRadiusAuthBackend_invalidNamespace tests error handling for non-existent namespace.
// This test requires Vault Enterprise as namespaces are an enterprise feature.
func TestAccRadiusAuthBackendConfig_invalidNamespace(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-invalid-ns")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRadiusAuthBackendConfig_invalidNamespace(path),
				ExpectError: regexp.MustCompile(`no handler for route`),
			},
		},
	})
}

func testAccRadiusAuthBackendConfig_namespace(ns, path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "test" {
	namespace = vault_namespace.test.path
	type      = "radius"
	path      = "%s"
}

resource "vault_radius_auth_backend" "test" {
  namespace = vault_namespace.test.path
	mount     = vault_auth_backend.test.path
	host      = %q
	secret_wo = %q
	secret_wo_version = %d
}
`, ns, path, testRadiusHost, testRadiusSecret, testRadiusSecretV1)
}

func testAccRadiusAuthBackendConfig_invalidNamespace(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  namespace = "nonexistent-namespace"
	mount     = "%s"
	host      = %q
	secret_wo = %q
	secret_wo_version = %d
}
`, path, testRadiusHost, testRadiusSecret, testRadiusSecretV1)
}
