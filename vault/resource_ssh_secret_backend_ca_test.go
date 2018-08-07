package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccSSHSecretBackendCA_basic(t *testing.T) {
	backend := "ssh-" + acctest.RandString(10)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckSSHSecretBackendCADestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendCAConfig(backend),
				Check:  testAccSSHSecretBackendCACheck(backend),
			},
		},
	})
}

func TestAccSecretBackend_import(t *testing.T) {
	backend := "ssh-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendCAConfig(backend),
				Check:  testAccSSHSecretBackendCACheck(backend),
			},
			{
				ResourceName:      "vault_ssh_secret_backend_ca.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckSSHSecretBackendCADestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ssh_secret_backend_ca" {
			continue
		}
		backend := rs.Primary.ID
		secret, err := client.Logical().Read(backend + "/config/ca")
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("CA information still exists for backend %q", rs.Primary.ID)
		}
	}
	return nil
}

func testAccSSHSecretBackendCAConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  type = "ssh"
  path = "%s"
}

resource "vault_ssh_secret_backend_ca" "test" {
  backend = "${vault_mount.test.path}"
}`, backend)
}

func testAccSSHSecretBackendCACheck(backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrSet("vault_ssh_secret_backend_ca.test", "public_key"),
		resource.TestCheckResourceAttr("vault_ssh_secret_backend_ca.test", "backend", backend),
	)
}
