// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldUsernameTemplate),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
			{
				Config: testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, "https://iam.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, "https://sts.us-west-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_noCreds(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
				),
			},
		},
	})
}

func TestAccAWSSecretBackend_wif(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_wifBasic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_wifUpdated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn-updated"),
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
	templ := fmt.Sprintf(`{{ printf \"vault-%%s-%%s-%%s\" (printf \"%%s-%%s\" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}`)
	expectedTempl := fmt.Sprintf(`{{ printf "vault-%%s-%%s-%%s" (printf "%%s-%%s" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}`)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, templ),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameTemplate, expectedTempl),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "86400"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_basic(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "86400"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
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
  description = "test description updated"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  access_key = "%s"
  secret_key = "%s"
  region = "us-west-1"

  iam_endpoint = "https://iam.amazonaws.com"
  sts_endpoint = "https://sts.us-west-1.amazonaws.com"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_wifBasic(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  identity_token_audience = "wif-audience"
  identity_token_ttl = 600
  role_arn = "test-role-arn"
}`, path)
}

func testAccAWSSecretBackendConfig_wifUpdated(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  identity_token_audience = "wif-audience-updated"
  identity_token_ttl = 1800
  role_arn = "test-role-arn-updated"
}`, path)
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
