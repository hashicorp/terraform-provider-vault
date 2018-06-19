package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestKubernetesAuthBackend(t *testing.T) {
	path := "kubernetes-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testKubernetesAuthCheckDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: initialKubernetesAuthConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "host", "test.host"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "ca_cert", "test cert"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "token_reviewer_jwt", "test jwt"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "pem_keys", "test keys"),
				),
			},
			{
				Config: updatedKubernetesAuthConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "description", "test updated description"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "host", "test updated host"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "ca_cert", "test updated cert"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "token_reviewer_jwt", "test updated jwt"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "pem_keys", "test updated keys"),
				),
			},
		},
	})
}

func initialKubernetesAuthConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_auth_backend" "test" {
    path = "%s"
    description = "test description"
    host = "test host"
    ca_cert = "test cert"
    token_reviewer_jwt = "test jwt"
    pem_keys = "test keys"
}
`, path)
}

func updatedKubernetesAuthConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path = "%s"
    description = "test updated description"
    host = "test updated host"
    ca_cert = "test updated cert"
    token_reviewer_jwt = "test updated jwt"
    pem_keys = "test updated keys"
}
`, path)
}

func testKubernetesAuthCheckDestroy(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}

		if _, ok := authMounts[fmt.Sprintf("%s/", path)]; ok {
			return fmt.Errorf("auth mount not destroyed")
		}

		return nil
	}
}
