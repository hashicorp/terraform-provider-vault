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

func TestKubernetesAuthRoleBackend(t *testing.T) {
	path := "kubernetes-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testKubernetesAuthRoleCheckDestroy(path, "test"),
		Steps: []resource.TestStep{
			{
				Config: initialKubernetesAuthRoleConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "path", path),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "name", "test"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.service_accounts", "0", "test_1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.namespaces", "0", "test_1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "max_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "period", "1800"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.policies", "0", "test_1"),
				),
			},
			{
				Config: updatedKubernetesAuthRoleConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "name", "test"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.service_accounts", "0", "test_1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.service_accounts", "1", "test_2"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.namespaces", "0", "test_2"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "ttl", "1800"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "max_ttl", "43200"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test", "period", "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.test.policies", "0", ""),
				),
			},
		},
	})
}

func initialKubernetesAuthRoleConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_auth_backend" "test" {
    path = "%s"
    host = "test host"
}

resource "vault_kubernetes_auth_backend_role" "test" {
    path = "${vault_kubernetes_auth_backend.test.path}"
    name = "test"
    ttl = "3600"
    max_ttl = "86400"
    period = "1800"

    service_accounts = [
        "test_1",
    ]

    namespaces = [
        "test_1",
    ]

    policies = [
        "test_1"
    ]
}
`, path)
}

func updatedKubernetesAuthRoleConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_auth_backend" "test" {
    path = "%s"
    host = "test host"
}

resource "vault_kubernetes_auth_backend_role" "test" {
    path = "${vault_kubernetes_auth_backend.test.path}"
    name = "test"
    ttl = "1800"
    max_ttl = "43200"
    period = "900"

    service_accounts = [
        "test_1",
        "test_2",
    ]

    namespaces = [
        "test_2",
    ]

    policies = [
    ]
}
`, path)
}

func testKubernetesAuthRoleCheckDestroy(path string, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		role, err := client.Logical().Read(fmt.Sprintf("/auth/%s/role/%s", path, name))
		if err != nil {
			return fmt.Errorf("Error reading Kubernetes role: %s", err)
		}
		if role != nil {
			return fmt.Errorf("Kubernetes role still exists")
		}

		return nil
	}
}
