// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "access_key", accessKey),
					resource.TestCheckResourceAttr(resourceName, "secret_key", secretKey),
					resource.TestCheckResourceAttr(resourceName, "region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "iam_endpoint", ""),
					resource.TestCheckResourceAttr(resourceName, "sts_endpoint", ""),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "username_template"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "secret_key", "disable_remount"),
			{
				Config: testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr(resourceName, "access_key", accessKey),
					resource.TestCheckResourceAttr(resourceName, "secret_key", secretKey),
					resource.TestCheckResourceAttr(resourceName, "region", "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, "iam_endpoint", "https://iam.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, "sts_endpoint", "https://sts.us-west-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_noCreds(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr(resourceName, "access_key", ""),
					resource.TestCheckResourceAttr(resourceName, "secret_key", ""),
					resource.TestCheckResourceAttr(resourceName, "region", "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, "iam_endpoint", ""),
					resource.TestCheckResourceAttr(resourceName, "sts_endpoint", ""),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
		},
	})
}

func TestAccAWSSecretBackend_usernameTempl(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	templ := fmt.Sprintf(`{{ printf "vault-%%s-%%s-%%s" (printf "%%s-%%s" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}`)
	updateTempl := fmt.Sprintf(`{{ printf "vault2-%%s-%%s-%%s" (printf "%%s-%%s" (.DisplayName) (.PolicyName) | truncate 41) (unix_time) (random 20) | truncate 63 }}`)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, templ),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "username_template", templ),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, updateTempl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "username_template", updateTempl),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "secret_key", "disable_remount"),
		},
	})
}

func TestAccAWSSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	updatedPath := acctest.RandomWithPrefix("tf-test-aws-updated")

	resourceName := "vault_aws_secret_backend.test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_basic(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "secret_key", "disable_remount"),
		},
	})
}

func testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  access_key = "%s"
  secret_key = "%s"
  region = "us-west-1"

  iam_endpoint = "https://iam.amazonaws.com"
  sts_endpoint = "https://sts.us-west-1.amazonaws.com"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_noCreds(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  region = "us-west-1"
}`, path)
}

func testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, templ string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
  username_template = "%s"
}`, path, accessKey, secretKey, templ)
}
