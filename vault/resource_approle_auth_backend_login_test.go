// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAppRoleAuthBackendLogin_basic(t *testing.T) {
	// Define the test cases for different token types.
	testCases := []struct {
		name          string
		tokenType     string
		accessorCheck resource.TestCheckFunc
	}{
		{
			name:      "Service",
			tokenType: "service",
			accessorCheck: resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
				"accessor"),
		},
		{
			name:      "Batch",
			tokenType: "batch",
			accessorCheck: resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
				"accessor", ""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := acctest.RandomWithPrefix("approle")
			role := acctest.RandomWithPrefix("test-role")

			resource.Test(t, resource.TestCase{
				PreCheck:          func() { testutil.TestAccPreCheck(t) },
				ProviderFactories: providerFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccAppRoleAuthBackendLoginConfig_basic(backend, role, tc.tokenType),
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
							tc.accessorCheck,
							resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
								"client_token"),
						),
					},
				},
			})
		})
	}

}

func testAccAppRoleAuthBackendLoginConfig_basic(backend, role string, tokenType string) string {

	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
  token_type = "%s"
  
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



`, backend, role, tokenType)

}
