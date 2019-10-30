package vault

import (
	"fmt"
	"testing"

	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
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
						"bound_service_account_names.64447719", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.64447719", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_ttl", "3600"),
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
						"bound_service_account_names.64447719", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.64447719", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.326271447", "dev"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_period", "0"),
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
						"bound_service_account_names.64447719", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.64447719", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", strconv.Itoa(maxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "900"),
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
						"bound_service_account_names.64447719", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_names.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.64447719", "example"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespaces.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.326271447", "dev"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_role.role",
						"token_period", "900"),
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
