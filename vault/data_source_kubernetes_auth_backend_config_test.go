package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccKubernetesAuthBackendConfigDataSource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	jwt := kubernetesJWT

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendConfigConfig_basic(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"kubernetes_host", "http://example.com:443"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"kubernetes_ca_cert", kubernetesCAcert),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt", jwt),
				),
			},
			{
				Config: testAccKubernetesAuthBackendConfigDataSourceConfig_basic(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckNoResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"kubernetes_host", "http://example.com:443"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"kubernetes_ca_cert", kubernetesCAcert),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "0"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendConfigDataSource_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	jwt := kubernetesJWT

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendConfigConfig_full(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"kubernetes_host", "http://example.com:443"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"kubernetes_ca_cert", kubernetesCAcert),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt", jwt),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"pem_keys.0", kubernetesPEMfile)),
			},
			{
				Config: testAccKubernetesAuthBackendConfigDataSourceConfig_full(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckNoResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"kubernetes_host", "http://example.com:443"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"kubernetes_ca_cert", kubernetesCAcert),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.0", kubernetesPEMfile),
				),
			},
		},
	})
}

func testAccKubernetesAuthBackendConfigDataSourceConfig_basic(backend, jwt string) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_config" "config" {
  backend = %q
}`, testAccKubernetesAuthBackendConfigConfig_basic(backend, jwt), backend)
}

func testAccKubernetesAuthBackendConfigDataSourceConfig_full(backend, jwt string) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_config" "config" {
  backend = "%s"
}`, testAccKubernetesAuthBackendConfigConfig_full(backend, jwt), backend)
}
