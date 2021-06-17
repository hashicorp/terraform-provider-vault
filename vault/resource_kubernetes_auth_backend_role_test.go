package vault

import (
	"fmt"
	"testing"

	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccKubernetesAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600
	audience := "vault"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, ttl, maxTTL, audience),
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
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", audience),
				),
			},
			{
				ResourceName:      "vault_kubernetes_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
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
		},
	})
}

func TestAccKubernetesAuthBackendRole_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	oldTTL := 3600
	newTTL := oldTTL * 2

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, oldTTL),
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
						"token_ttl", strconv.Itoa(oldTTL)),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, newTTL),
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
						"token_ttl", strconv.Itoa(newTTL)),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600
	audience := "vault"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, ttl, maxTTL, audience),
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
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", audience),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	oldTTL := 3600
	newTTL := oldTTL * 2
	oldMaxTTL := 3600
	newMaxTTL := oldMaxTTL * 2
	oldAudience := "vault"
	newAudience := "new-vault"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, oldTTL, oldMaxTTL, oldAudience),
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
						"token_ttl", strconv.Itoa(oldTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", strconv.Itoa(oldMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", oldAudience),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, newTTL, newMaxTTL, newAudience),
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
						"token_ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", newAudience),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, newTTL, newMaxTTL, newAudience),
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
						"token_ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", newAudience),
				),
			},
			// Unset `token_max_ttl`
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role, newTTL, newAudience),
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
						"token_ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", newAudience),
				),
			},
			// Unset `audience`
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role, newTTL, ""),
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
						"token_ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", ""),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_fullDeprecated(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	oldTTL := 3600
	newTTL := oldTTL * 2
	oldMaxTTL := 3600
	newMaxTTL := oldMaxTTL * 2
	oldAudience := "vault"
	newAudience := "new-vault"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_fullDeprecated(backend, role, oldTTL, oldMaxTTL, oldAudience),
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
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"ttl", strconv.Itoa(oldTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(oldMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", oldAudience),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_fullDeprecated(backend, role, newTTL, newMaxTTL, newAudience),
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
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"audience", newAudience),
				),
			},
		},
	})
}

func testAccCheckKubernetesAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kubernetes_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Kubernetes auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Kubernetes auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccKubernetesAuthBackendRoleConfig_basic(backend, role string, ttl int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = "${vault_auth_backend.kubernetes.path}"
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
}`, backend, role, ttl)
}

func testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role string, ttl int, audience string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = "${vault_auth_backend.kubernetes.path}"
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
  audience = %q
}`, backend, role, ttl, audience)
}

func testAccKubernetesAuthBackendRoleConfig_full(backend, role string, ttl, maxTTL int, audience string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = "${vault_auth_backend.kubernetes.path}"
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl = %d
  token_max_ttl = %d
  token_period = 900
  token_policies = ["default", "dev", "prod"]
  audience = %q
}`, backend, role, ttl, maxTTL, audience)
}

func testAccKubernetesAuthBackendRoleConfig_fullDeprecated(backend, role string, ttl, maxTTL int, audience string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = "${vault_auth_backend.kubernetes.path}"
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  ttl = %d
  max_ttl = %d
  period = 900
  policies = ["default", "dev", "prod"]
  audience = %q
}`, backend, role, ttl, maxTTL, audience)
}
