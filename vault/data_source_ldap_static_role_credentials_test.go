// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceLDAPStaticRoleCredentials(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-static-role-credentials")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	dn := "cn=alice,ou=users,dc=example,dc=org"
	username := "alice"
	dataName := "data.vault_ldap_static_credentials.creds"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		Steps: []resource.TestStep{
			{
				Config: testLDAPStaticRoleDataSource(backend, bindDN, bindPass, url, username, dn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationPeriod, "60"),
					resource.TestCheckResourceAttr(dataName, consts.FieldLastPassword, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldDN, dn),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldPassword),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldTTL),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastVaultRotation),
				),
			},
			// second 1.16 gated check
			{
				SkipFunc: func() (bool, error) {
					return !provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion116), nil
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataName, consts.FieldSkipImportRotation),
				),
			},
		},
	})
}

func testLDAPStaticRoleDataSource(path, bindDN, bindPass, url, username, dn string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount = vault_ldap_secret_backend.test.path
  username = "%s"
  dn = "%s"
  role_name = "%s"
  rotation_period = 60
}

data "vault_ldap_static_credentials" "creds" {
  mount = vault_ldap_secret_backend.test.path
  role_name  = vault_ldap_secret_backend_static_role.role.role_name
}
`, path, bindDN, bindPass, url, username, dn, username)
}
