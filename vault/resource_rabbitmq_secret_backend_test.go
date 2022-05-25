package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccRabbitMQSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resourceName := "vault_rabbitmq_secret_backend.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccRabbitMQSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendConfig_basic(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "connection_uri", connectionUri),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"connection_uri", "username", "password", "verify_connection"},
			},
			{
				Config: testAccRabbitMQSecretBackendConfig_updated(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr(resourceName, "connection_uri", connectionUri),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
				),
			},
		},
	})
}

func TestAccRabbitMQSecretBackend_template(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resourceName := "vault_rabbitmq_secret_backend.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccRabbitMQSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendTemplateConfig(path, connectionUri, username, password, path, path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "connection_uri", connectionUri),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
					resource.TestCheckResourceAttr(resourceName, "password_policy", path),
					resource.TestCheckResourceAttr(resourceName, "username_template", path),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"connection_uri", "username", "password", "verify_connection"},
			},
		},
	})
}

func testAccRabbitMQSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

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

func testAccRabbitMQSecretBackendConfig_basic(path, connectionUri, username, password string) string {
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

func testAccRabbitMQSecretBackendConfig_updated(path, connectionUri, username, password string) string {
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

func testAccRabbitMQSecretBackendTemplateConfig(path, connectionUri, username, password, uTemplate, passPolicy string) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path              = "%s"
  connection_uri    = "%s"
  username          = "%s"
  password          = "%s"
  username_template = "%s"
  password_policy   = "%s"
}`, path, connectionUri, username, password, uTemplate, passPolicy)
}
