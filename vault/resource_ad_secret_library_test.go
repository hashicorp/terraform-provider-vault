// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccADSecretBackendLibrary_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccADSecretBackendLibraryCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendLibraryConfig(backend, bindDN, bindPass, url, "qa", `"Bob","Mary"`, 60, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "disable_check_in_enforcement", "false"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "max_ttl", "120"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.1", "Mary"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.#", "2"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "ttl", "60"),
				),
			},
			{
				Config: testADSecretBackendLibraryConfig(backend, bindDN, bindPass, url, "qa", `"Bob"`, 120, 240, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "disable_check_in_enforcement", "true"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "max_ttl", "240"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "ttl", "120"),
				),
			},
		},
	})
}

func TestAccADSecretBackendLibrary_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccADSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendLibraryConfig(backend, bindDN, bindPass, url, "qa", `"Bob","Mary"`, 60, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "disable_check_in_enforcement", "false"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "max_ttl", "120"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.0", "Bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.1", "Mary"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "service_account_names.#", "2"),
					resource.TestCheckResourceAttr("vault_ad_secret_library.test", "ttl", "60"),
				),
			},
			{
				ResourceName:      "vault_ad_secret_library.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccADSecretBackendLibraryCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ad_secret_library" {
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

func testADSecretBackendLibraryConfig(backend, bindDN, bindPass, url, name, serviceAccountNames string, ttl, maxTTL int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	binddn = "%s"
	bindpass = "%s"
	url = "%s"
	insecure_tls = "true"
	userdn = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ad_secret_library" "test" {
    backend = vault_ad_secret_backend.config.backend
    name = "%s"
    service_account_names = [%s]
    ttl = %d
    max_ttl = %d
    disable_check_in_enforcement = %t
}
`, backend, bindDN, bindPass, url, name, serviceAccountNames, ttl, maxTTL, disable)
}
