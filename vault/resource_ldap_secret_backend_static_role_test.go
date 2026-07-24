// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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

func TestAccLDAPSecretBackendStaticRole_PasswordPolicy(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-static-role")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"
	username := "alice"
	dn := "cn=alice,dc=example,dc=org"
	rotationPeriod := "60"
	passwordPolicy := "test-password-policy"
	updatedPasswordPolicy := "updated-password-policy"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig_passwordPolicy(path, bindDN, bindPass, url, username, dn, username, rotationPeriod, passwordPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordPolicy, passwordPolicy),
				),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig_passwordPolicy(path, bindDN, bindPass, url, username, dn, username, rotationPeriod, updatedPasswordPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordPolicy, updatedPasswordPolicy),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName, consts.FieldSkipImportRotation),
			{
				Config: testLDAPSecretBackendStaticRoleConfig_withSkip(path, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordPolicy, ""),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName, consts.FieldSkipImportRotation, consts.FieldPasswordPolicy),
		},
	})
}

// TestAccLDAPSecretBackendStaticRole_autoUnlock verifies the per-role auto_unlock
// override semantics: a role-level value takes precedence over the mount-level
// setting. auto_unlock is Active Directory only and requires Vault 2.1+,
// so this test is gated on VaultVersion210 and AD_* env vars.
func TestAccLDAPSecretBackendStaticRole_autoUnlock(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-static-role")
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"

	envVars := testutil.SkipTestEnvUnset(t, "AD_URL", "AD_STATIC_ROLE_DN", "AD_STATIC_ROLE_USERNAME")
	url := envVars[0]
	dn := envVars[1]
	username := envVars[2]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				// mount enables auto_unlock, role overrides it to false.
				Config: testLDAPSecretBackendStaticRoleConfig_autoUnlock(path, url, username, dn, username, "true", "false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoUnlock, "false"),
				),
			},
			{
				// role override flips to true, winning over the mount default.
				Config: testLDAPSecretBackendStaticRoleConfig_autoUnlock(path, url, username, dn, username, "false", "true"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoUnlock, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

// TestLDAPSecretBackendStaticRoleResource_autoUnlockSchema is a unit test (no live
// Vault required) confirming the static-role resource exposes the auto_unlock field
// with Optional+Computed semantics so that an unset value inherits the mount setting.
func TestLDAPSecretBackendStaticRoleResource_autoUnlockSchema(t *testing.T) {
	s := ldapSecretBackendStaticRoleResource().Schema
	field, ok := s[consts.FieldAutoUnlock]
	if !ok {
		t.Fatalf("expected %q field in static-role resource schema", consts.FieldAutoUnlock)
	}
	if field.Type != schema.TypeBool {
		t.Errorf("expected %q to be TypeBool, got %v", consts.FieldAutoUnlock, field.Type)
	}
	if !field.Optional {
		t.Errorf("expected %q to be Optional", consts.FieldAutoUnlock)
	}
	if !field.Computed {
		t.Errorf("expected %q to be Computed (to inherit the mount-level value when unset)", consts.FieldAutoUnlock)
	}
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

func testLDAPSecretBackendStaticRoleConfig_passwordPolicy(mount, bindDN, bindPass, url, username, dn, role, rotationPeriod, passwordPolicy string) string {
	return fmt.Sprintf(`
resource "vault_password_policy" "test" {
  name   = "%s"
  policy = "length=20\nrule \"charset\" { charset = \"abcdefghijklmnopqrstuvwxyz\" min-chars = 1 }"
}

resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "dc=example,dc=org"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount               = vault_ldap_secret_backend.test.path
  username            = "%s"
  dn                  = "%s"
  role_name           = "%s"
  rotation_period     = %s
  password_policy     = vault_password_policy.test.name
  skip_import_rotation = true
}
`, passwordPolicy, mount, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}

func TestAccLDAPSecretBackendStaticRole_RotateOnRead(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-static-role")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"
	username := "alice"
	dn := "cn=alice,ou=users,dc=example,dc=org"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig_rotateOnRead(path, bindDN, bindPass, url, username, dn, "true", "60"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotateOnRead, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotateOnReadCooldown, "60"),
				),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig_rotateOnRead(path, bindDN, bindPass, url, username, dn, "true", "120"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotateOnRead, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotateOnReadCooldown, "120"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldMount, consts.FieldRoleName, consts.FieldSkipImportRotation),
		},
	})
}

func testLDAPSecretBackendStaticRoleConfig_rotateOnRead(mount, bindDN, bindPass, url, username, dn, rotateOnRead, cooldown string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path     = "%s"
  binddn   = "%s"
  bindpass = "%s"
  url      = "%s"
  userdn   = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount                    = vault_ldap_secret_backend.test.path
  username                 = "%s"
  dn                       = "%s"
  role_name                = "%s"
  rotation_period          = 60
  rotate_on_read           = %s
  rotate_on_read_cooldown  = %s
  skip_import_rotation     = true
}
`, mount, bindDN, bindPass, url, username, dn, username, rotateOnRead, cooldown)
}

// testLDAPSecretBackendStaticRoleConfig_autoUnlock builds an Active Directory mount
// and static role with configurable mount-level and role-level auto_unlock values,
// used to exercise the per-role override semantics.
func testLDAPSecretBackendStaticRoleConfig_autoUnlock(mount, url, username, dn, role, mountAutoUnlock, roleAutoUnlock string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%s"
  binddn       = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net"
  bindpass     = "SuperSecretPassw0rd"
  url          = "%s"
  insecure_tls = "true"
  userdn       = "CN=Users,DC=corp,DC=example,DC=net"
  schema       = "ad"
  auto_unlock  = %s
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount           = vault_ldap_secret_backend.test.path
  username        = "%s"
  dn              = "%s"
  role_name       = "%s"
  rotation_period = 60
  auto_unlock     = %s
}
`, mount, url, mountAutoUnlock, username, dn, role, roleAutoUnlock)
}
