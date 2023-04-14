// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

/*
To test, run the openldap service provided in the docker-compose.yaml file:

	docker compose up -d openldap

Then export the following environment variables:

	LDAP_BINDDN=cn=admin,dc=example,dc=org
	LDAP_BINDPASS=adminpassword
	LDAP_URL=ldap://localhost:1389
*/
func TestLDAPSecretBackend(t *testing.T) {
	var (
		mount                 = acctest.RandomWithPrefix("tf-test-ldap")
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
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendConfig(mount, description, bindDN, bindPass, url, userDN, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, description),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
				),
			},
			{
				Config: testLDAPSecretBackendConfig(mount, updatedDescription, bindDN, bindPass, url, updatedUserDN, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, updatedDescription),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, updatedUserDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"bindpass", "schema", consts.FieldDescription, consts.FieldDisableRemount),
		},
	})
}

func testLDAPSecretBackendConfig(mount, description, bindDN, bindPass, url, userDN string, insecureTLS bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  mount                     = "%s"
  description               = "%s"
  default_lease_ttl_seconds = "3600"
  max_lease_ttl_seconds     = "7200"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "%s"
  insecure_tls              = %v
}
`, mount, description, bindDN, bindPass, url, userDN, insecureTLS)
}
