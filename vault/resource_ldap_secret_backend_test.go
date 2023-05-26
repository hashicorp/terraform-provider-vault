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
		userDN                = "CN=Users,DC=corp,DC=example,DC=net"
		updatedUserDN         = "CN=Users,DC=corp,DC=hashicorp,DC=com"
	)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		}, PreventPostDestroyRefresh: true,
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig_defaults(bindDN, bindPass),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "openldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, "ldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, description),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, "ldap://127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig(path, description, bindDN, bindPass, url, userDN, "ad", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "ad"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, description),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "99"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig(path, updatedDescription, bindDN, bindPass, url, updatedUserDN, "ad", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSchema, "ad"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, updatedDescription),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
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

// testLDAPSecretBackendConfig_defaults is used to setup the backend defaults.
func testLDAPSecretBackendConfig_defaults(bindDN, bindPass string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
}`, bindDN, bindPass)
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
