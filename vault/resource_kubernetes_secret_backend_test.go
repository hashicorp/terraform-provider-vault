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

func TestAccKubernetesSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-kubernetes")
	resourceName := "vault_kubernetes_secret_backend.test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	addr := lns[0].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKubernetesSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKubernetesSecretBackend_initialConfig(path, addr),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "kubernetes_host", addr),
					resource.TestCheckResourceAttr(resourceName, "disable_local_ca_jwt", "false"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "3600"),
				),
			},
			{
				Config: testKubernetesSecretBackend_updateConfig(path, addr),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description updated"),
					resource.TestCheckResourceAttr(resourceName, "kubernetes_host", addr),
					resource.TestCheckResourceAttr(resourceName, "disable_local_ca_jwt", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "7200"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"path", "description", "default_lease_ttl",
				},
			},
		},
	})
}

func testAccKubernetesSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kubernetes_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "kubernetes" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}

	return nil
}

func testKubernetesSecretBackend_initialConfig(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                 = "%s"
  description          = "test description"
  default_lease_ttl    = 3600
  kubernetes_host      = "%s"
  disable_local_ca_jwt = false
}`, path, addr)
}

func testKubernetesSecretBackend_updateConfig(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                 = "%s"
  description          = "test description updated"
  default_lease_ttl    = 7200
  kubernetes_host      = "%s"
  disable_local_ca_jwt = true
}`, path, addr)
}
