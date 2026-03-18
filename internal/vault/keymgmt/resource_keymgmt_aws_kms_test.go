// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
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
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	awsRegion := testutil.GetTestAWSRegion(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, awsRegion, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", awsRegion),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAWSKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentials,
					consts.FieldCredentialsWOVersion,
				},
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_keyCollectionChange(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, "us-west-2", accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", "us-west-2"),
				),
			},
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, "us-east-1", accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", "us-east-1"),
				),
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_envCredentials(t *testing.T) {
	awsRegion := testutil.GetTestAWSRegion(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfigNoCredentials(mount, kmsName, awsRegion),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", awsRegion),
				),
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_multiple(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

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
				Config: testKeymgmtAWSKMSConfigMultiple(mount, kmsName1, kmsName2, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, kmsName1),
					resource.TestCheckResourceAttr(resourceName1, "key_collection", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, mount),
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
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/kms/%s", mount, name), nil
	}
}

func testKeymgmtAWSKMSConfigNoCredentials(mount, kmsName, region string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
}
`, mount, kmsName, region)
}

func testKeymgmtAWSKMSConfig(mount, kmsName, region, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}
`, mount, kmsName, region, accessKey, secretKey)
}

func testKeymgmtAWSKMSConfigMultiple(mount, kmsName1, kmsName2, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test1" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = "us-west-2"

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_aws_kms" "test2" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = "us-east-1"

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}
`, mount, kmsName1, accessKey, secretKey,
		kmsName2, accessKey, secretKey)
}
