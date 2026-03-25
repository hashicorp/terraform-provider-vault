// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func testAccRadiusAuthBackendUserConfigWithBody(backend, userBody string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "radius"
	path = %q
}

resource "vault_radius_auth_backend_user" "test" {
%s
}
`, backend, userBody)
}

func testAccRadiusAuthBackendUserNamespacedConfigWithBody(namespace, backend, userBody string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = %q
}

resource "vault_auth_backend" "test" {
	namespace = vault_namespace.test.path
	type      = "radius"
	path      = %q
}

resource "vault_radius_auth_backend_user" "test" {
	namespace = vault_namespace.test.path
%s
}
`, namespace, backend, userBody)
}

func TestAccRadiusAuthBackendUser_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("radius")
	username := acctest.RandomWithPrefix("user")
	resourceType := "vault_radius_auth_backend_user"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendUserConfig_basic(backend, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "default"),
				),
			},
			{
				Config: testAccRadiusAuthBackendUserConfig_updated(backend, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "dev"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "prod"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/users/%s", backend, username),
				ImportStateVerifyIdentifierAttribute: "mount",
			},
		},
	})
}

func TestAccRadiusAuthBackendUser_noPolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("radius")
	username := acctest.RandomWithPrefix("user")
	resourceType := "vault_radius_auth_backend_user"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendUserConfig_noPolicies(backend, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldPolicies+".#"),
				),
			},
		},
	})
}

func testAccRadiusAuthBackendUserConfig_basic(backend, username string) string {
	return testAccRadiusAuthBackendUserConfigWithBody(backend, fmt.Sprintf(`
	mount    = vault_auth_backend.test.path
	username = %q
	policies = ["default"]
`, username))
}

func testAccRadiusAuthBackendUserConfig_updated(backend, username string) string {
	return testAccRadiusAuthBackendUserConfigWithBody(backend, fmt.Sprintf(`
	mount    = vault_auth_backend.test.path
	username = %q
	policies = ["dev", "prod"]
`, username))
}

func testAccRadiusAuthBackendUserConfig_noPolicies(backend, username string) string {
	return testAccRadiusAuthBackendUserConfigWithBody(backend, fmt.Sprintf(`
	mount    = vault_auth_backend.test.path
	username = %q
`, username))
}

func TestAccRadiusAuthBackendUser_namespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("radius")
	username := acctest.RandomWithPrefix("user")
	namespace := acctest.RandomWithPrefix("ns")
	resourceName := "vault_radius_auth_backend_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendUserConfig_namespace(backend, username, namespace),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "default"),
				),
			},
		},
	})
}

func TestAccRadiusAuthBackendUser_invalid(t *testing.T) {
	backend := acctest.RandomWithPrefix("radius")
	username := acctest.RandomWithPrefix("user")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test invalid mount
			{
				Config:      testAccRadiusAuthBackendUserConfig_invalidMount(username),
				ExpectError: regexp.MustCompile("no handler for route|unsupported path"),
			},
			// Test missing username
			{
				Config:      testAccRadiusAuthBackendUserConfig_missingUsername(backend),
				ExpectError: regexp.MustCompile(`(?i)(?=.*username)(?=.*required)`),
			},
			// Test missing mount
			{
				Config:      testAccRadiusAuthBackendUserConfig_missingMount(),
				ExpectError: regexp.MustCompile(`(?i)(?=.*mount)(?=.*required)`),
			},
		},
	})
}

func TestAccRadiusAuthBackendUser_invalidNamespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("radius")
	username := acctest.RandomWithPrefix("user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRadiusAuthBackendUserConfig_invalidNamespace(backend, username),
				ExpectError: regexp.MustCompile("no handler for route|namespace not found|route entry not found"),
			},
		},
	})
}

func testAccRadiusAuthBackendUserConfig_invalidMount(username string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend_user" "test" {
  mount    = "nonexistent-mount"
  username = "%s"
  policies = ["default"]
}
`, username)
}

func testAccRadiusAuthBackendUserConfig_missingUsername(backend string) string {
	return testAccRadiusAuthBackendUserConfigWithBody(backend, `
	mount    = vault_auth_backend.test.path
	policies = ["default"]
`)
}

func testAccRadiusAuthBackendUserConfig_missingMount() string {
	return `
resource "vault_radius_auth_backend_user" "test" {
  username = "testuser"
  policies = ["default"]
}
`
}

func testAccRadiusAuthBackendUserConfig_invalidNamespace(backend, username string) string {
	return testAccRadiusAuthBackendUserConfigWithBody(backend, fmt.Sprintf(`
	namespace = "nonexistent-namespace"
	mount     = vault_auth_backend.test.path
	username  = %q
	policies  = ["default"]
`, username))
}

func testAccRadiusAuthBackendUserConfig_namespace(backend, username, namespace string) string {
	return testAccRadiusAuthBackendUserNamespacedConfigWithBody(namespace, backend, fmt.Sprintf(`
	mount     = vault_auth_backend.test.path
	username  = %q
	policies  = ["default"]
`, username))
}
