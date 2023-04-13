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

func TestAccLDAPSecretBackendStaticRole(t *testing.T) {
	var (
		backend               = acctest.RandomWithPrefix("tf-test-ldap-static-role")
		bindDN, bindPass, url = testutil.GetTestLDAPCreds(t)
		resourceType          = "vault_ldap_secret_backend_static_role"
		resourceName          = resourceType + ".role"
		username              = "alice"
		dn                    = "cn=alice,ou=users,dc=example,dc=org"
		rotationPeriod        = "60"
		updatedUsername       = "bob"
		updatedDN             = "cn=bob,ou=users,dc=example,dc=org"
		updatedRotationPeriod = "120"
	)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig(backend, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
				),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig(backend, bindDN, bindPass, url, updatedUsername, updatedDN, updatedUsername, updatedRotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, updatedDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, updatedUsername),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, updatedRotationPeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldBackend, consts.FieldRole, consts.FieldDisableRemount),
		},
	})
}

func testLDAPSecretBackendStaticRoleConfig(backend, bindDN, bindPass, url, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
    backend = vault_ldap_secret_backend.test.backend
    username = "%s"
    dn = "%s"
    role = "%s"
    rotation_period = %s
}
`, backend, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}
