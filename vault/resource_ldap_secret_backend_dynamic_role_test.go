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

var (
	creationLDIF = `dn: cn={{.Username}},ou=users,dc=example,dc=org
objectClass: person
objectClass: top
cn: learn
sn: {{.Password | utf16le | base64}}
userPassword: {{.Password}}`
	deletionLDIF = `dn: cn={{.Username}},ou=users,dc=example,dc=org
changetype: delete`
	rollbackLDIF = deletionLDIF
)

func TestAccLDAPSecretBackendDynamicRole(t *testing.T) {
	var p *schema.Provider
	roleName := acctest.RandomWithPrefix("tf-test-ldap-dynamic-role")
	bindDN, bindPass, _ := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_dynamic_role"
	resourceName := resourceType + ".role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendDynamicRoleConfig_defaults(roleName, bindDN, bindPass),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldCreationLDIF, creationLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionLDIF, deletionLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRollbackLDIF, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameTemplate, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultTTL, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "20"),
				),
			},
			{
				Config: testLDAPSecretBackendDynamicRoleConfig(roleName, bindDN, bindPass, "20", "40"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldCreationLDIF, creationLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionLDIF, deletionLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRollbackLDIF, rollbackLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameTemplate, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

// testLDAPSecretBackendDynamicRoleConfig_defaults sets up default and required
// fields.
func testLDAPSecretBackendDynamicRoleConfig_defaults(roleName, bindDN, bindPass string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
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
  default_ttl   = 10
  max_ttl       = 20
}
`, bindDN, bindPass, roleName, creationLDIF, deletionLDIF)
}

func testLDAPSecretBackendDynamicRoleConfig(roleName, bindDN, bindPass, defaultTTL, maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
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
`, bindDN, bindPass, roleName, creationLDIF, deletionLDIF, rollbackLDIF, defaultTTL, maxTTL)
}
