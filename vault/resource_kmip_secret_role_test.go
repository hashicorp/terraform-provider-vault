package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretRole_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-kmip")
	resourceName := "vault_kmip_secret_role.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKMIPSecretRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretRole_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, "tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "operation_activate", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_get", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_get_attributes", "true"),
				),
			},
			{
				Config: testKMIPSecretRole_updatedConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, "tls_client_key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "tls_client_key_bits", "4096"),
					resource.TestCheckResourceAttr(resourceName, "operation_activate", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_get", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_get_attributes", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_get_attribute_list", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_create", "true"),
					resource.TestCheckResourceAttr(resourceName, "operation_destroy", "true"),
				),
			},
		},
	})
}

func testAccKMIPSecretRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kmip_secret_role" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "kmip" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}

	return nil
}

func testKMIPSecretRole_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  description = "test description"
}

resource "vault_kmip_secret_scope" "scope-1" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "scope-1"
}

resource "vault_kmip_secret_role" "test" {
    path = vault_kmip_secret_scope.scope-1.path
    scope = "scope-1"
    role = "test"
	tls_client_key_type = "ec"
 	tls_client_key_bits = 256
	operation_activate = true
    operation_get = true
    operation_get_attributes = true
}


`, path)
}

func testKMIPSecretRole_updatedConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  description = "test description"
}

resource "vault_kmip_secret_scope" "scope-1" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "scope-1"
}

resource "vault_kmip_secret_role" "test" {
    path = vault_kmip_secret_scope.scope-1.path
    scope = "scope-1"
    role = "test"
	tls_client_key_type = "rsa"
 	tls_client_key_bits = 4096
	operation_activate = true
    operation_get = true
    operation_get_attributes = true
	operation_get_attribute_list = true
	operation_create = true
	operation_destroy = true
}


`, path)
}
