// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccLDAPSecretBackendStaticRole(t *testing.T) {
	var (
		path                  = acctest.RandomWithPrefix("tf-test-ldap-static-role")
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig(path, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					return !testProvider.Meta().(*provider.ProviderMeta).IsAPISupported(provider.VaultVersion116), nil
				},
				Config: testLDAPSecretBackendStaticRoleConfig_withSkip(path, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check:  resource.TestCheckResourceAttr(resourceName, consts.FieldSkipImportRotation, "true"),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig(path, bindDN, bindPass, url, updatedUsername, updatedDN, updatedUsername, updatedRotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, updatedDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, updatedUsername),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, updatedRotationPeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

func TestAccLDAPSecretBackendStaticRole_SelfManaged(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-static-role")
	bindDN, _, url := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"
	envVars := testutil.SkipTestEnvUnset(t, "LDAP_DN", "LDAP_SM_USERNAME", "LDAP_SM_PASSWORD")
	dn := envVars[0]
	username := envVars[1]
	password := envVars[2]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion200)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig_selfManaged(path, bindDN, url, dn, username, password, "1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPolicy, "test-policy"),
				),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig_selfManagedUpdated(path, bindDN, url, dn, username, password, "1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPolicy, "test-policy-updated"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName,
				consts.FieldSkipImportRotation,
				consts.FieldPasswordWOVersion),
		},
	})
}

func testLDAPSecretBackendStaticRoleConfig(mount, bindDN, bindPass, url, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount            = vault_ldap_secret_backend.test.path
  username        = "%s"
  dn              = "%s"
  role_name       = "%s"
  rotation_period = %s
}
`, mount, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}

func testLDAPSecretBackendStaticRoleConfig_withSkip(mount, bindDN, bindPass, url, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount            = vault_ldap_secret_backend.test.path
  username        = "%s"
  dn              = "%s"
  role_name       = "%s"
  rotation_period = %s
  skip_import_rotation = true
}
`, mount, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}

func testLDAPSecretBackendStaticRoleConfig_selfManaged(mount, bindDN, url, dn, username, password, passwordVersion string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
  self_managed              = true
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount                = vault_ldap_secret_backend.test.path
  username             = "%s"
  dn                   = "%s"
  role_name            = "%s"
  rotation_period      = 60
  password_wo          = "%s"
  password_wo_version  = %s
  rotation_policy      = "test-policy"
}
`, mount, bindDN, url, username, dn, username, password, passwordVersion)
}

func testLDAPSecretBackendStaticRoleConfig_selfManagedUpdated(mount, bindDN, url, dn, username, password, passwordVersion string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
  self_managed              = true
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount                = vault_ldap_secret_backend.test.path
  username             = "%s"
  dn                   = "%s"
  role_name            = "%s"
  rotation_period      = 120
  password_wo          = "%s"
  password_wo_version  = %s
  rotation_policy      = "test-policy-updated"
}
`, mount, bindDN, url, username, dn, username, password, passwordVersion)
}
