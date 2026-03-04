// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtAWSKMS(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	awsRegion := "us-west-2"
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		awsRegion = region
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, awsRegion),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", awsRegion),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAWSKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					consts.FieldAccessKey,
					consts.FieldSecretKey,
				},
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_keyCollectionChange(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, "us-west-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", "us-west-2"),
				),
			},
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, "us-east-1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", "us-east-1"),
				),
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_credentialsMap(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfigWithCredentialsMap(mount, kmsName, "us-west-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", "us-west-2"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAWSKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					"credentials",
				},
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_multiple(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName1 := acctest.RandomWithPrefix("awskms-1")
	kmsName2 := acctest.RandomWithPrefix("awskms-2")
	resourceName1 := "vault_keymgmt_aws_kms.test1"
	resourceName2 := "vault_keymgmt_aws_kms.test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfigMultiple(mount, kmsName1, kmsName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, kmsName1),
					resource.TestCheckResourceAttr(resourceName1, "key_collection", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, kmsName2),
					resource.TestCheckResourceAttr(resourceName2, "key_collection", "us-east-1"),
				),
			},
		},
	})
}

func testAccKeymgmtAWSKMSImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		path := rs.Primary.Attributes[consts.FieldPath]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/kms/%s", path, name), nil
	}
}

func testKeymgmtAWSKMSConfig(mount, kmsName, region string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  
  access_key = "%s"
  secret_key = "%s"
}
`, mount, kmsName, region, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

func testKeymgmtAWSKMSConfigWithCredentialsMap(mount, kmsName, region string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  
  credentials = {
    access_key = "%s"
    secret_key = "%s"
  }
}
`, mount, kmsName, region, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

func testKeymgmtAWSKMSConfigMultiple(mount, kmsName1, kmsName2 string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test1" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = "us-west-2"
  
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_keymgmt_aws_kms" "test2" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = "us-east-1"
  
  access_key = "%s"
  secret_key = "%s"
}
`, mount, kmsName1, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"),
		kmsName2, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}
