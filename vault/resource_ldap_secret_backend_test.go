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

func TestLDAPSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)

	resourceType := "vault_ldap_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		}, PreventPostDestroyRefresh: true,
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackend_initialConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, "CN=Users,DC=corp,DC=example,DC=net"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCaseSensitiveNames, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
				),
			},
			{
				Config: testLDAPSecretBackend_updateConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "new test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "14400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPass, bindPass),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, "CN=Users,DC=corp,DC=hashicorp,DC=com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCaseSensitiveNames, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"bindpass", "schema", consts.FieldDescription, consts.FieldDisableRemount),
		},
	})
}

func testLDAPSecretBackend_initialConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  default_lease_ttl_seconds = "3600"
  max_lease_ttl_seconds     = "7200"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
  insecure_tls              = true
}
`, backend, bindDN, bindPass, url)
}

func testLDAPSecretBackend_updateConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  backend                   = "%s"
  description               = "new test description"
  default_lease_ttl_seconds = "7200"
  max_lease_ttl_seconds     = "14400"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=hashicorp,DC=com"
  insecure_tls              = false
}
`, backend, bindDN, bindPass, url)
}
