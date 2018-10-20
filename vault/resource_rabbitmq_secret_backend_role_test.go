package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/terraform"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/vault/api"
)

const testAccRabbitmqSecretBackendRoleTags_basic = `management`
const testAccRabbitmqSecretBackendRoleTags_updated = `management,policymaker`
const testAccRabbitmqSecretBackendRoleVhost_basic = "{\"/\": {\"configure\":\"\", \"write\":\"\", \"read\": \".*\"}}"
const testAccRabbitmqSecretBackendRoleVhost_updated = "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"

func TestAccRabbitmqSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri := "http://" + acctest.RandString(10) + ":15672"
	username := acctest.RandString(10)
	password := acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "vhost", testAccRabbitmqSecretBackendRoleVhost_basic),
				),
			},
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "tags", testAccRabbitmqSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "vhost", testAccRabbitmqSecretBackendRoleVhost_updated),
				),
			},
		},
	})
}

func TestAccRabbitmqSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri := "http://" + acctest.RandString(10) + ":15672"
	username := acctest.RandString(10)
	password := acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "vhost", testAccRabbitmqSecretBackendRoleVhost_basic),
				),
			},
			{
				ResourceName:      "vault_rabbitmq_secret_backend_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRabbitmqSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri := "http://" + acctest.RandString(10) + ":15672"
	username := acctest.RandString(10)
	password := acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "vhost", testAccRabbitmqSecretBackendRoleVhost_basic),
				),
			},
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "tags", testAccRabbitmqSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend_role.test", "vhost", testAccRabbitmqSecretBackendRoleVhost_updated),
				),
			},
		},
	})
}

func testAccRabbitmqSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_rabbitmq_secret_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccRabbitmqSecretBackendRoleConfig_basic(name, path, connectionUri, username, password string) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  connection_uri = "%s"
  username = "%s"
  password = "%s"
}

resource "vault_rabbitmq_secret_backend_role" "test" {
  name = "%s"
  tags = %q
  vhost = %q
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_basic, testAccRabbitmqSecretBackendRoleVhost_basic)
}

func testAccRabbitmqSecretBackendRoleConfig_updated(name, path, connectionUri, username, password string) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  connection_uri = "%s"
  username = "%s"
  password = "%s"
}

resource "vault_rabbitmq_secret_backend_role" "test" {
  name = "%s"
  tags = %q
  vhost = %q
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_updated, testAccRabbitmqSecretBackendRoleVhost_updated)
}
