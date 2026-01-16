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
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.2", "prod"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"role_id"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"secret_id"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"renewable"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"lease_started"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"accessor"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"client_token"),
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
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.2", "prod"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"role_id"),
					// secret_id_wo should NOT appear in state
					resource.TestCheckNoResourceAttr("vault_approle_auth_backend_login.test",
						consts.FieldSecretIDWO),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						consts.FieldSecretIDWOVersion, "1"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"renewable"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"lease_started"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"accessor"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"client_token"),
				),
			},
			{
				// Update with new version to trigger re-authentication
				Config: testAccAppRoleAuthBackendLoginConfig_writeOnly(backend, role, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						consts.FieldSecretIDWOVersion, "2"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"accessor"),
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
