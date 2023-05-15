// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccLdapSecretBackendLibrarySet_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccLdapSecretBackendLibrarySetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLdapSecretBackendLibrarySetConfig(path, bindDN, bindPass, url, "qa", `"Bob","Mary"`, 60, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "disable_check_in_enforcement", "false"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "max_ttl", "120"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.1", "Mary"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.#", "2"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "ttl", "60"),
				),
			},
			{
				Config: testADSecretBackendLibraryConfig(path, bindDN, bindPass, url, "qa", `"Bob"`, 120, 240, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "disable_check_in_enforcement", "true"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "max_ttl", "240"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "ttl", "120"),
				),
			},
		},
	})
}

func TestAccLdapSecretBackendLibrarySet_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccADSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLdapSecretBackendLibrarySetConfig(backend, bindDN, bindPass, url, "qa", `"Bob","Mary"`, 60, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "disable_check_in_enforcement", "false"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "max_ttl", "120"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.1", "Mary"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "service_account_names.#", "2"),
					resource.TestCheckResourceAttr("vault_ldap_secret_backend_library_set.test", "ttl", "60"),
				),
			},
			{
				ResourceName:      "vault_ldap_secret_backend_library_set.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccLdapSecretBackendLibrarySetCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_secret_backend_library_set" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("library %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLdapSecretBackendLibrarySetConfig(path, bindDN, bindPass, url, name, serviceAccountNames string, ttl, maxTTL int, disable bool) string {
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

resource "vault_ldap_secret_backend_library_set" "test" {
    backend = vault_ldap_secret_backend.path
    name = "%s"
    service_account_names = [%s]
    ttl = %d
    max_ttl = %d
    disable_check_in_enforcement = %t
}
`, path, bindDN, bindPass, url, name, serviceAccountNames, ttl, maxTTL, disable)
}
