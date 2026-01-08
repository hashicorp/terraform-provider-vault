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
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

/*
To test, run the openldap service provided in the docker-compose.yaml file:

	docker compose up -d openldap

Then export the following environment variables:

	export LDAP_BINDDN=cn=admin,dc=example,dc=org
	export LDAP_BINDPASS=adminpassword
	export LDAP_URL=ldap://localhost:1389
*/
func TestLDAPSecretBackend(t *testing.T) {
	var (
		path                  = acctest.RandomWithPrefix("tf-test-ldap")
		bindDN, bindPass, url = testutil.GetTestLDAPCreds(t)
		resourceType          = "vault_ldap_secret_backend"
		resourceName          = resourceType + ".test"
		description           = "test description"
		updatedDescription    = "new test description"
		updatedUserDN         = "CN=Users,DC=corp,DC=hashicorp,DC=com"
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		}, PreventPostDestroyRefresh: true,
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig_defaults(path, bindDN, bindPass),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "openldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, description),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, "ldap://127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					return !testProvider.Meta().(*provider.ProviderMeta).IsAPISupported(provider.VaultVersion116), nil
				},
				Config: testLDAPSecretBackendConfig_withSkip(path, bindDN, bindPass),
				Check:  resource.TestCheckResourceAttr(resourceName, consts.FieldSkipStaticRoleImportRotation, "true"),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !(meta.IsAPISupported(provider.VaultVersion118) && meta.IsEnterpriseSupported()), nil
				},
				Config: testLDAPSecretBackendConfig_defaults(path, bindDN, bindPass),
				Check:  resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialType, "password"),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !(meta.IsAPISupported(provider.VaultVersion118) && meta.IsEnterpriseSupported()), nil
				},
				Config: testLDAPSecretBackendConfig_withCredType(path, bindDN, bindPass),
				Check:  resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialType, "phrase"),
			},
			{
				Config: testLDAPSecretBackendConfig(path, updatedDescription, bindDN, bindPass, url, updatedUserDN, "openldap", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "openldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, updatedDescription),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, updatedUserDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "99"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldBindPass, consts.FieldConnectionTimeout, consts.FieldDescription, consts.FieldDisableRemount),
		},
	})
}

func TestLDAPSecretBackend_bindpassWO(t *testing.T) {
	var (
		path                = acctest.RandomWithPrefix("tf-test-ldap-wo")
		bindDN, bindPass, _ = testutil.GetTestLDAPCreds(t)
		resourceType        = "vault_ldap_secret_backend"
		resourceName        = resourceType + ".test"
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig_bindpassWO(path, bindDN, bindPass, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "1"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig_bindpassWO(path, bindDN, "updated-password", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldBindPassWO,
				consts.FieldBindPassWOVersion,
				consts.FieldConnectionTimeout,
				consts.FieldDescription,
				consts.FieldDisableRemount,
			),
		},
	})
}

func TestLDAPSecretBackend_bindpassConflict(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("tf-test-ldap-bindpass-conflict")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testLDAPSecretBackendConfig_bindpassConflict(path),
				ExpectError: regexp.MustCompile("Invalid combination of arguments"),
				Destroy:     false,
			},
		},
	})
}

// TestLDAPSecretBackend_SchemaAD tests vault_ldap_secret_backend for the AD
// schema and tests that the bindpass is not overwritten unless it is
// explicitly changed in the TF config so that we don't clobber a bindpass that
// was changed via a rotate-root operation in Vault.
//
// To test, run the ad service provided in the docker-compose.yaml file:
//
//	docker compose up -d ad
//
// Then export the following environment variables:
//
// export AD_URL=ldaps://localhost:2636
func TestLDAPSecretBackend_SchemaAD(t *testing.T) {
	var (
		path         = acctest.RandomWithPrefix("tf-test-ldap")
		resourceType = "vault_ldap_secret_backend"
		resourceName = resourceType + ".test"
		userDN       = "CN=Users,DC=corp,DC=example,DC=net"
		bindPass     = "SuperSecretPassw0rd"
		bindDN       = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net"

		url = testutil.SkipTestEnvUnset(t, "AD_URL")[0]
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig_ad(path, url, ""),
				Check: resource.ComposeTestCheckFunc(
					func(*terraform.State) error {
						client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
						if _, err := client.Logical().Write(path+"/rotate-root", nil); err != nil {
							return err
						}
						return nil
					},
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "ad"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig_ad(path, url, `description = "new description"`),
				Check: resource.ComposeTestCheckFunc(
					func(*terraform.State) error {
						client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
						if _, err := client.Logical().Write(path+"/rotate-root", nil); err != nil {
							return err
						}
						return nil
					},
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "ad"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "new description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),

					// Even though we did a rotate-root, we expect the TF state
					// to have no change for bindpass because we did not
					// explicitly change it in the config and it is not
					// returned by the Vault API.
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
				),
			},
			{
				Config: testLDAPSecretBackendConfig_ad_updated(path, url, `description = "new description"`),
				Check: resource.ComposeTestCheckFunc(
					// We explicitly updated the bindpass in the TF config so
					// we expect the state to contain the new value.
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, "NEW-SuperSecretPassw0rd"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldBindPass, consts.FieldConnectionTimeout, consts.FieldDisableRemount),
		},
	})
}

func TestLDAPSecretBackend_automatedRotation(t *testing.T) {
	var (
		path                = acctest.RandomWithPrefix("tf-test-ldap")
		bindDN, bindPass, _ = testutil.GetTestLDAPCreds(t)
		resourceType        = "vault_ldap_secret_backend"
		resourceName        = resourceType + ".test"
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		}, PreventPostDestroyRefresh: true,
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig_automatedRotation(path, bindDN, bindPass, "* * * * *", 50, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "* * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "50"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig_automatedRotation(path, bindDN, bindPass, "", 0, 100, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "100"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldBindPass, consts.FieldConnectionTimeout, consts.FieldDescription, consts.FieldDisableRemount),
		},
	})
}

// testLDAPSecretBackendConfig_defaults is used to setup the backend defaults.
func testLDAPSecretBackendConfig_defaults(path, bindDN, bindPass string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
}`, path, bindDN, bindPass)
}

func testLDAPSecretBackendConfig_withSkip(path, bindDN, bindPass string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  skip_static_role_import_rotation = true
}`, path, bindDN, bindPass)
}

func testLDAPSecretBackendConfig_withCredType(path, bindDN, bindPass string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path            = "%s"
  description     = "test description"
  binddn          = "%s"
  bindpass        = "%s"
  credential_type = "phrase"
}`, path, bindDN, bindPass)
}

func testLDAPSecretBackendConfig(mount, description, bindDN, bindPass, url, userDN, schema string, insecureTLS bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "%s"
  default_lease_ttl_seconds = "3600"
  max_lease_ttl_seconds     = "7200"
  binddn                    = "%s"
  bindpass                  = "%s"
  connection_timeout        = "99"
  url                       = "%s"
  userdn                    = "%s"
  insecure_tls              = %v
  schema                    = "%s"
}
`, mount, description, bindDN, bindPass, url, userDN, insecureTLS, schema)
}

func testLDAPSecretBackendConfig_ad(path, url, extraConfig string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%s"
  binddn       = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net"
  bindpass     = "SuperSecretPassw0rd"
  url          = "%s"
  insecure_tls = "true"
  userdn       = "CN=Users,DC=corp,DC=example,DC=net"
  schema       = "ad"
  %s
}
`, path, url, extraConfig)
}

func testLDAPSecretBackendConfig_ad_updated(path, url, extraConfig string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%s"
  binddn       = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net"
  bindpass     = "NEW-SuperSecretPassw0rd"
  url          = "%s"
  insecure_tls = "true"
  userdn       = "CN=Users,DC=corp,DC=example,DC=net"
  schema       = "ad"
  %s
}
`, path, url, extraConfig)
}

// testLDAPSecretBackendConfig_defaults is used to setup the backend defaults.
func testLDAPSecretBackendConfig_automatedRotation(path, bindDN, bindPass, schedule string, window, period int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  rotation_schedule         = "%s"
  rotation_window           = "%d"
  rotation_period           = "%d"
  disable_automated_rotation = %t
}`, path, bindDN, bindPass, schedule, window, period, disable)
}

func testLDAPSecretBackendConfig_bindpassWO(path, bindDN, bindPass string, version int) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                 = "%s"
  description          = "test description with write-only bindpass"
  binddn               = "%s"
  bindpass_wo          = "%s"
  bindpass_wo_version  = %d
}`, path, bindDN, bindPass, version)
}

func testLDAPSecretBackendConfig_bindpassConflict(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                 = "%s"
  description          = "test description with conflicting bindpass"
  binddn               = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net"
  bindpass             = "supersecurepassword"
  bindpass_wo          = "anothersecurepassword"
  bindpass_wo_version  = 1
}`, path)
}
