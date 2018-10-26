package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
)

func TestAccKubernetesAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
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
						"ttl", strconv.Itoa(oldTTL)),
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
						"ttl", strconv.Itoa(newTTL)),
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

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
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

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, oldTTL, oldMaxTTL),
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
						"ttl", strconv.Itoa(oldTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(oldMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"period", "900"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, newTTL, newMaxTTL),
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
						"ttl", strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"max_ttl", strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"period", "900"),
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
  ttl = %d
  policies = ["default", "dev", "prod"]
}`, backend, role, ttl)
}

func testAccKubernetesAuthBackendRoleConfig_full(backend, role string, ttl, maxTTL int) string {
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
}`, backend, role, ttl, maxTTL)
}
