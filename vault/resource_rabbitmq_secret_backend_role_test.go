// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	testAccRabbitMQSecretBackendRoleTags_basic   = `management`
	testAccRabbitMQSecretBackendRoleTags_updated = `management,policymaker`
)

func TestAccRabbitMQSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccRabbitMQSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_basic),
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
				Config: testAccRabbitMQSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ".*"),
				),
			},
		},
	})
}

func TestAccRabbitMQSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccRabbitMQSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendRoleConfig_basic(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_basic),
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
				Config: testAccRabbitMQSecretBackendRoleConfig_updated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_updated),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.host", "/"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.configure", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.read", ".*"),
					resource.TestCheckResourceAttr(resourceName, "vhost.0.write", ".*"),
				),
			},
		},
	})
}

func TestAccRabbitMQSecretBackendRole_topic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-rabbitmq")
	name := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resourceName := "vault_rabbitmq_secret_backend_role.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccRabbitMQSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendRoleConfig_topics(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_basic),
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
				Config: testAccRabbitMQSecretBackendRoleConfig_topicUpdated(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", testAccRabbitMQSecretBackendRoleTags_updated),
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

func testAccRabbitMQSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_rabbitmq_secret_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

func testAccRabbitMQSecretBackendRoleConfig_basic(name, path, connectionUri, username, password string) string {
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
`, path, connectionUri, username, password, name, testAccRabbitMQSecretBackendRoleTags_basic)
}

func testAccRabbitMQSecretBackendRoleConfig_updated(name, path, connectionUri, username, password string) string {
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
`, path, connectionUri, username, password, name, testAccRabbitMQSecretBackendRoleTags_updated)
}

func testAccRabbitMQSecretBackendRoleConfig_topics(name, path, connectionUri, username, password string) string {
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
`, path, connectionUri, username, password, name, testAccRabbitMQSecretBackendRoleTags_basic)
}

func testAccRabbitMQSecretBackendRoleConfig_topicUpdated(name, path, connectionUri, username, password string) string {
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
`, path, connectionUri, username, password, name, testAccRabbitMQSecretBackendRoleTags_updated)
}

func TestFlattenRabbitMQSecretBackendRoleVhost_Order(t *testing.T) {
	input := map[string]interface{}{
		"b-vhost": map[string]interface{}{
			"configure": "c1",
			"read":      "r1",
			"write":     "w1",
		},
		"a-vhost": map[string]interface{}{
			"configure": "c2",
			"read":      "r2",
			"write":     "w2",
		},
		"c-vhost": map[string]interface{}{
			"configure": "c3",
			"read":      "r3",
			"write":     "w3",
		},
	}

	result := flattenRabbitMQSecretBackendRoleVhost(input)

	expectedOrder := []string{"a-vhost", "b-vhost", "c-vhost"}
	if len(result) != len(expectedOrder) {
		t.Fatalf("expected %d vhosts, got %d", len(expectedOrder), len(result))
	}
	for i, expectedHost := range expectedOrder {
		if result[i]["host"] != expectedHost {
			t.Errorf("expected host at index %d to be %q, got %q", i, expectedHost, result[i]["host"])
		}
	}
}
