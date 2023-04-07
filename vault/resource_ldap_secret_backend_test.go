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
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			{
				Config: testLDAPSecretBackend_updateConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "new test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=hashicorp,DC=com"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"bindpass", "description", "disable_remount"),
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
}
`, backend, bindDN, bindPass, url)
}
