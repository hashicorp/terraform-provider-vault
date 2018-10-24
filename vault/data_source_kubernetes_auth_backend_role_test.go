package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"strconv"
)

func TestAccKubernetesAuthBackendRoleDataSource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, ttl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"ttl", "3600"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleDataSourceConfig_basic(backend, role, ttl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.0", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.0", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.2", "prod"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"max_ttl", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"num_uses", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"period", "0"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRoleDataSource_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, ttl, maxTTL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(maxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"period", "900"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleDataSourceConfig_full(backend, role, ttl, maxTTL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.0", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.0", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.2", "prod"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"num_uses", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"period", "900"),
				),
			},
		},
	})
}

func testAccKubernetesAuthBackendRoleDataSourceConfig_basic(backend, role string, ttl int) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_role" "role" {
  backend = %q
  role_name = %q
}`, testAccKubernetesAuthBackendRoleConfig_basic(backend, role, ttl), backend, role)
}

func testAccKubernetesAuthBackendRoleDataSourceConfig_full(backend, role string, ttl, maxTTL int) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_role" "role" {
  backend = %q
  role_name = %q
}`, testAccKubernetesAuthBackendRoleConfig_full(backend, role, ttl, maxTTL), backend, role)
}
