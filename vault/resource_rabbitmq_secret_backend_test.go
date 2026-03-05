// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

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
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, password),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{consts.FieldConnectionURI, consts.FieldUsername, consts.FieldPassword, consts.FieldVerifyConnection, consts.FieldDisableRemount},
			},
			{
				Config: testAccRabbitMQSecretBackendConfig_updated(path, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, password),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, password),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordPolicy, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameTemplate, path),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{consts.FieldConnectionURI, consts.FieldUsername, consts.FieldPassword, consts.FieldVerifyConnection, consts.FieldDisableRemount},
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, password),
				),
			},
			{
				Config: testAccRabbitMQSecretBackendConfig_basic(updatedPath, connectionUri, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, password),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDescription, consts.FieldUsername,
				consts.FieldPassword, consts.FieldVerifyConnection, consts.FieldDisableRemount),
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

func TestAccRabbitMQSecretBackend_passwordWriteOnly(t *testing.T) {
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
				Config: testAccRabbitMQSecretBackendConfig_passwordWO(path, connectionUri, username, password, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionURI, connectionUri),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordWOVersion, "1"),
				),
			},
			{
				Config: testAccRabbitMQSecretBackendConfig_passwordWO(path, connectionUri, username, password, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPasswordWOVersion, "2"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldConnectionURI, consts.FieldUsername, consts.FieldVerifyConnection, consts.FieldDisableRemount,
					consts.FieldPasswordWO, consts.FieldPasswordWOVersion,
				},
			},
		},
	})
}

func testAccRabbitMQSecretBackendConfig_passwordWO(path, connectionUri, username, password string, version int) string {
	return fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path                = "%s"
  description         = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  connection_uri      = "%s"
  username            = "%s"
  password_wo         = "%s"
  password_wo_version = %d
}`, path, connectionUri, username, password, version)
}

func TestAccRabbitMQSecretBackend_passwordConflicts(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-rabbitmq")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_rabbitmq_secret_backend" "test" {
  path                = "%s"
  connection_uri      = "https://localhost:15672"
  username            = "admin"
  password            = "test-password"
  password_wo         = "test-password-wo"
  password_wo_version = 1
}`, path),
				ExpectError: regexp.MustCompile(`Invalid combination of arguments|only one of`),
			},
		},
	})
}
