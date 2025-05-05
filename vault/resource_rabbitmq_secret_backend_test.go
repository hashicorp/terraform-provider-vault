// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccRabbitMQSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	connectionUri, username, password := testutil.GetTestRMQCreds(t)
	resourceType := "vault_rabbitmq_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeRabbitMQ, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendConfig_basic(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
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
				ImportStateVerifyIgnore: []string{"connection_uri", "username", "password", "verify_connection", "disable_remount"},
			},
			{
				Config: testAccRabbitMQSecretBackendConfig_updated(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
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
	resourceType := "vault_rabbitmq_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeRabbitMQ, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccRabbitMQSecretBackendTemplateConfig(path, connectionUri, username, password, path, path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
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
				ImportStateVerifyIgnore: []string{"connection_uri", "username", "password", "verify_connection", "disable_remount"},
			},
		},
	})
}

func TestRabbitMQSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	updatedPath := acctest.RandomWithPrefix("tf-test-rabbitmq-updated")

	resourceName := "vault_rabbitmq_secret_backend.test"
	connectionUri, username, password := testutil.GetTestRMQCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
				Config: testAccRabbitMQSecretBackendConfig_basic(updatedPath, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "connection_uri", connectionUri),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "username",
				"password", "verify_connection", "disable_remount"),
		},
	})
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
