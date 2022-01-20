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

func TestAccKMIPSecretBackendScope_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-kmip")
	resourceName := "vault_kmip_secret_backend_scope.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKMIPSecretBackendScopeCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretBackendScope_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "scope", "test"),
				),
			},
		},
	})
}

func testAccKMIPSecretBackendScopeCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kmip_secret_backend_scope" {
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

func testKMIPSecretBackendScope_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  description = "test description"
}

resource "vault_kmip_secret_backend_scope" "test" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "test"
}`, path)
}
