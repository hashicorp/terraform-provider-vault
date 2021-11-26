package vault

import (
	"testing"

	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccRabbitmqSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri, username, password := getTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccRabbitmqSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendConfig_basic(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "connection_uri", connectionUri),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "username", username),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "password", password),
				),
			},
			{
				Config: testAccRabbitmqSecretBackendConfig_updated(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "connection_uri", connectionUri),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "username", username),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "password", password),
				),
			},
		},
	})
}

func TestAccRabbitmqSecretBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri, username, password := getTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccRabbitmqSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitmqSecretBackendConfig_basic(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "connection_uri", connectionUri),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "username", username),
					resource.TestCheckResourceAttr("vault_rabbitmq_secret_backend.test", "password", password),
				),
			},
			{
				ResourceName:      "vault_rabbitmq_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"connection_uri", "username", "password", "verify_connection"},
			},
		},
	})
}

func testAccRabbitmqSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_rabbitmq_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "rabbitmq" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}
	return nil
}

func testAccRabbitmqSecretBackendConfig_basic(path, connectionUri, username, password string) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  connection_uri = "%s"
  username = "%s"
  password = "%s"
}`, path, connectionUri, username, password)
}

func testAccRabbitmqSecretBackendConfig_updated(path, connectionUri, username, password string) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  connection_uri = "%s"
  username = "%s"
  password = "%s"
}`, path, connectionUri, username, password)
}
