// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccLdapSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resourceType := "vault_ldap_secret_backend.test"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLdapSecretBackend_createConfig(path, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "description", "disable_remount"),
			{
				Config: testLdapSecretBackend_updateConfig(path, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=hashicorp,DC=com"),
				),
			},
		},
	})
}

func testLdapSecretBackend_createConfig(path, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
	path                   	  = "%s"
	description               = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds     = "7200"
	binddn                    = "%s"
	bindpass                  = "%s"
	url                       = "%s"
	insecure_tls              = "true"
	userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}
`, path, bindDN, bindPass, url)
}

func testLdapSecretBackend_updateConfig(path, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
	path                      = "%s"
	description               = "test description"
	default_lease_ttl_seconds = "7200"
	max_lease_ttl_seconds     = "14400"
	binddn                    = "%s"
	bindpass                  = "%s"
	url                       = "%s"
	insecure_tls              = "false"
	userdn                    = "CN=Users,DC=corp,DC=hashicorp,DC=com"
}
`, path, bindDN, bindPass, url)
}
