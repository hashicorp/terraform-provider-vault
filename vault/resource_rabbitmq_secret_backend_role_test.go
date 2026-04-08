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

func TestAccRabbitMQSecretBackendRole_multipleVhostsAndTopics(t *testing.T) {
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
				Config: testAccRabbitMQSecretBackendRoleConfig_multipleVhostsAndTopics(name, backend, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "tags", "management"),
					// Verify we have 11 vhost blocks
					resource.TestCheckResourceAttr(resourceName, "vhost.#", "11"),
					// Check that specific vhosts are present (TypeSet doesn't guarantee order)
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost.*", map[string]string{
						"host":      "cosmos",
						"read":      "^toto$",
						"write":     "^toto$",
						"configure": "^toto$",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost.*", map[string]string{
						"host":      "customer",
						"read":      "^toto$",
						"write":     "^toto$",
						"configure": "^toto$",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost.*", map[string]string{
						"host":      "ship",
						"read":      "^toto$",
						"write":     "^toto$",
						"configure": "^toto$",
					}),
					// Verify we have 3 vhost_topic blocks
					resource.TestCheckResourceAttr(resourceName, "vhost_topic.#", "3"),
					// Check vhost_topic hosts are present
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost_topic.*", map[string]string{
						"host": "/",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost_topic.*", map[string]string{
						"host": "cosmos",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "vhost_topic.*", map[string]string{
						"host": "customers",
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccRabbitMQSecretBackendRoleConfig_multipleVhostsAndTopics(name, path, connectionUri, username, password string) string {
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
  tags = "management"
  
  vhost {
    host      = "cosmos"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "customer"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "demand"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "ei"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "es"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "leg"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "mulan"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "mulan_test"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "op-t"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "pub"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost {
    host      = "ship"
    read      = "^toto$"
    write     = "^toto$"
    configure = "^toto$"
  }
  
  vhost_topic {
    host = "/"
    vhost {
      topic = "amq.topic"
      read  = ".*"
      write = ".*"
    }
  }

  vhost_topic {
    host = "cosmos"
    vhost {
      topic = "amq.topic"
      read  = "^cosmos.*"
      write = "^cosmos.*"
    }
    vhost {
      topic = "amq.direct"
      read  = ".*"
      write = ""
    }
  }

  vhost_topic {
    host = "customers"
    vhost {
      topic = "customer.events"
      read  = ".*"
      write = "^customer\\..*"
    }
  }
}
`, path, connectionUri, username, password, name)
}
