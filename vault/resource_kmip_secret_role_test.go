package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

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
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_updatedConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "4096"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
		},
	})
}

func TestAccKMIPSecretRole_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-kmip")
	remountPath := acctest.RandomWithPrefix("tf-test-kmip-remount")
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
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_initialConfig(remountPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", remountPath),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
		},
	})
}

func testAccKMIPSecretRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*ProviderMeta).GetClient()

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
