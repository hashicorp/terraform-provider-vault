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

func TestAccADSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccADSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendRoleConfig(backend, bindDN, bindPass, url, "bob", "Bob", 60),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_ad_secret_role.role", "password_last_set"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "role", "bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "service_account_name", "Bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "ttl", "60"),
				),
			},
			{
				Config: testADSecretBackendRoleConfig(backend, bindDN, bindPass, url, "bob", "Bob", 120),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_ad_secret_role.role", "password_last_set"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "role", "bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "service_account_name", "Bob"),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "ttl", "120"),
				),
			},
		},
	})
}

func TestAccADSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)
	role := "bob"
	serviceAccountName := "Bob"
	ttl := 60

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccADSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendRoleConfig(backend, bindDN, bindPass, url, role, serviceAccountName, ttl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "role", role),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "service_account_name", serviceAccountName),
					resource.TestCheckResourceAttr("vault_ad_secret_role.role", "ttl", fmt.Sprintf("%d", ttl)),
				),
			},
			{
				ResourceName:      "vault_ad_secret_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccADSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ad_secret_role" {
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
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testADSecretBackendRoleConfig(backend, bindDN, bindPass, url, role, serviceAccountName string, ttl int) string {
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

resource "vault_ad_secret_role" "role" {
    backend = vault_ad_secret_backend.config.backend
    role = "%s"
    service_account_name = "%s"
    ttl = %d
}
`, backend, bindDN, bindPass, url, role, serviceAccountName, ttl)
}
