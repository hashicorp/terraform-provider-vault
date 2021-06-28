package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

func TestAccGCPAuthBackendRoleDataSource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("gcp")
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	serviceAccount := acctest.RandomWithPrefix("tf-test-gcp-service-account")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"role", name),
				),
			},
			{
				Config: testAccGCPAuthBackendRoleDataSourceConfig_basic(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"role_name", name),
					resource.TestCheckResourceAttrSet("data.vault_gcp_auth_backend_role.gcp_role",
						"role_id"),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"bound_service_accounts.#", "1"),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttrSet("data.vault_gcp_auth_backend_role.gcp_role",
						"token_ttl"),
					resource.TestCheckResourceAttrSet("data.vault_gcp_auth_backend_role.gcp_role",
						"token_max_ttl"),
					resource.TestCheckResourceAttrSet("data.vault_gcp_auth_backend_role.gcp_role",
						"token_num_uses"),
				),
			},
		},
	})
}

func TestAccGCPAuthBackendRoleDataSource_gce(t *testing.T) {
	backend := acctest.RandomWithPrefix("gcp")
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_gce(backend, name, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"bound_labels.#", "2"),
				),
			},
			{
				Config: testAccGCPAuthBackendRoleDataSourceConfig_basic(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"role_name", name),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"type", "gce"),
					resource.TestCheckResourceAttrSet("data.vault_gcp_auth_backend_role.gcp_role",
						"role_id"),
					resource.TestCheckResourceAttr("data.vault_gcp_auth_backend_role.gcp_role",
						"bound_labels.#", "2"),
				),
			},
		},
	})
}

func testAccGCPAuthBackendRoleDataSourceConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
data "vault_gcp_auth_backend_role" "gcp_role" {
  backend = "%s"
  role_name = "%s"
}`, backend, role)
}
