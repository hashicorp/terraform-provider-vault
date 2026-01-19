// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const testAppRoleAuthBackendLoginResource = "vault_approle_auth_backend_login.test"

func TestAccAppRoleAuthBackendLogin_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendLoginConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".#", "3"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".0", "default"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".1", "dev"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".2", "prod"),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldRoleID),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldSecretID),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldRenewable),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldAccessor),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldClientToken),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendLogin_writeOnly(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendLoginConfig_writeOnly(backend, role, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".#", "3"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".0", "default"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".1", "dev"),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldPolicies+".2", "prod"),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldRoleID),
					// secret_id_wo should NOT appear in state
					resource.TestCheckNoResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldSecretIDWO),
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldSecretIDWOVersion, "1"),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldRenewable),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldAccessor),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldClientToken),
				),
			},
			{
				// Update with new version to trigger re-authentication
				Config: testAccAppRoleAuthBackendLoginConfig_writeOnly(backend, role, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAppRoleAuthBackendLoginResource,
						consts.FieldSecretIDWOVersion, "2"),
					resource.TestCheckResourceAttrSet(testAppRoleAuthBackendLoginResource,
						consts.FieldAccessor),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendLogin_ConflictingFields(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testAccAppRoleAuthBackendLoginConfig_conflicting(backend, role),
				ExpectError: regexp.MustCompile(`"secret_id": conflicts with secret_id_wo|"secret_id_wo": conflicts with secret_id`),
			},
		},
	})
}

func testAccAppRoleAuthBackendLoginConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret" {
  backend = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

resource "vault_approle_auth_backend_login" "test" {
  backend = vault_auth_backend.approle.path
  role_id = vault_approle_auth_backend_role.role.role_id
  secret_id = vault_approle_auth_backend_role_secret_id.secret.secret_id
}
`, backend, role)
}

func testAccAppRoleAuthBackendLoginConfig_writeOnly(backend, role string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret" {
  backend = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

resource "vault_approle_auth_backend_login" "test" {
  backend = vault_auth_backend.approle.path
  role_id = vault_approle_auth_backend_role.role.role_id
  secret_id_wo = vault_approle_auth_backend_role_secret_id.secret.secret_id
  secret_id_wo_version = %d
}
`, backend, role, version)
}

func testAccAppRoleAuthBackendLoginConfig_conflicting(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret" {
  backend = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

resource "vault_approle_auth_backend_login" "test" {
  backend = vault_auth_backend.approle.path
  role_id = vault_approle_auth_backend_role.role.role_id
  secret_id = vault_approle_auth_backend_role_secret_id.secret.secret_id
  secret_id_wo = vault_approle_auth_backend_role_secret_id.secret.secret_id
}
`, backend, role)
}
