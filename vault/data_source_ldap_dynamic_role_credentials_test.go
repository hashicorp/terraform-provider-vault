// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceLDAPDynamicRoleCredentials(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-dynamic-role-credentials")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	dataName := "data.vault_ldap_dynamic_credentials.creds"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		Steps: []resource.TestStep{
			{
				Config: testLDAPDynamicRoleDataSource(path, path, bindDN, bindPass, url, "100", "100"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataName, consts.FieldPassword),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldUsername),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLeaseID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLeaseRenewable),
				),
			},
		},
	})
}
func testLDAPDynamicRoleDataSource(path, roleName, bindDN, bindPass, url, defaultTTL, maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
}

resource "vault_ldap_secret_backend_dynamic_role" "role" {
  mount         = vault_ldap_secret_backend.test.path
  role_name     = "%s"
  creation_ldif = <<EOT
%s
EOT
  deletion_ldif = <<EOT
%s
EOT
  rollback_ldif = <<EOT
%s
EOT
  default_ttl   = %s
  max_ttl       = %s
}

data "vault_ldap_dynamic_credentials" "creds" {
  mount = vault_ldap_secret_backend.test.path
  role_name  = vault_ldap_secret_backend_dynamic_role.role.role_name
}
`, path, bindDN, bindPass, url, roleName, creationLDIF, deletionLDIF, rollbackLDIF, defaultTTL, maxTTL)
}
