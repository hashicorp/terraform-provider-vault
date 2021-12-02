package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	testAccRabbitmqSecretBackendRoleTags_basic   = `management`
	testAccRabbitmqSecretBackendRoleTags_updated = `management,policymaker`
)

func TestAccRabbitmqSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ""),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ".*"),
				),
			},
		},
	})
}

func TestAccRabbitmqSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ""),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ".*"),
				),
			},
		},
	})
}

func TestAccRabbitmqSecretBackendRole_topic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.testAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_topics(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_basic),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.topic", "amq.topic"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.write", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccRabbitmqSecretBackendRoleConfig_topicUpdated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitmqSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.topic", "amq.topic"),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.read", ""),
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.0.vhost.0.write", ".*"),
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
  backend = vault_rabbitmq_secret_backend.test.path
  name = "%s"
  tags = %q
  vhost {
    host = "/"
    configure = ""
    read = ".*"
    write = ""
  }
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_basic)
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
  backend = vault_rabbitmq_secret_backend.test.path
  name = "%s"
  tags = %q
  vhost {
    host = "/"
    configure = ".*"
    read = ".*"
    write = ".*"
  }
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_updated)
}

func testAccRabbitmqSecretBackendRoleConfig_topics(name, path, connectionUri, username, password string) string {
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
  backend = vault_rabbitmq_secret_backend.test.path
  name = "%s"
  tags = %q
    
  vhost_topic {
    vhost {
		topic = "amq.topic"
		read = ".*"
		write = ""
	}
	
	host = "/"
  }
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_basic)
}

func testAccRabbitmqSecretBackendRoleConfig_topicUpdated(name, path, connectionUri, username, password string) string {
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
  backend = vault_rabbitmq_secret_backend.test.path
  name = "%s"
  tags = %q
  vhost_topic {
    vhost {
		topic = "amq.topic"
		read = ""
		write = ".*"
	}
	
	host = "/"
  }
}
`, path, connectionUri, username, password, name, testAccRabbitmqSecretBackendRoleTags_updated)
}
