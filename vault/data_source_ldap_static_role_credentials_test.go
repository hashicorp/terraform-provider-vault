// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

func TestAccDataSourceLDAPStaticRoleCredentials(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-static-role-credentials")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	dn := "cn=alice,ou=users,dc=example,dc=org"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testLDAPStaticRoleDataSource(backend, bindDN, bindPass, url, "alice", dn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_ldap_static_credentials.creds", "username", "alice"),
					resource.TestCheckResourceAttr("data.vault_ldap_static_credentials.creds", "rotation_period", "60"),
					resource.TestCheckResourceAttr("data.vault_ldap_static_credentials.creds", "last_password", ""),
					resource.TestCheckResourceAttr("data.vault_ldap_static_credentials.creds", "dn", dn),
					resource.TestCheckResourceAttrSet("data.vault_ldap_static_credentials.creds", "password"),
					resource.TestCheckResourceAttrSet("data.vault_ldap_static_credentials.creds", "ttl"),
					resource.TestCheckResourceAttrSet("data.vault_ldap_static_credentials.creds", "last_vault_rotation"),
				),
			},
		},
	})
}

func testLDAPStaticRoleDataSource(backend, bindDN, bindPass, url, username, dn string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
}

resource "vault_ldap_secret_backend_static_role" "role" {
    backend = vault_ldap_secret_backend.test.backend
    username = "%s"
    dn = "%s"
    role = "%s"
    rotation_period = 60
}

data "vault_ldap_static_credentials" "creds" {
  backend = vault_ldap_secret_backend.test.backend
  role    = vault_ldap_secret_backend_static_role.role.role
}
`, backend, bindDN, bindPass, url, username, dn, username)
}
