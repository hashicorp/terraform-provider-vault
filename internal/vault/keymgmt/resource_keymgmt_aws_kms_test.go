// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"regexp"
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyCollection, awsRegion),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAWSKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentialsWO,
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyCollection, "us-west-2"),
				),
			},
			{
				Config: testKeymgmtAWSKMSConfig(mount, kmsName, "us-east-1", accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyCollection, "us-east-1"),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyCollection, awsRegion),
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
					resource.TestCheckResourceAttr(resourceName1, consts.FieldKeyCollection, "us-west-2"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, kmsName2),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldKeyCollection, "us-east-1"),
				),
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_namespace(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	awsRegion := testutil.GetTestAWSRegion(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	namespace := acctest.RandomWithPrefix("test-namespace")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAWSKMSConfigNamespace(namespace, mount, kmsName, awsRegion, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyCollection, awsRegion),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAWSKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentialsWO,
					consts.FieldCredentialsWOVersion,
				},
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
			},
			{
				// Cleanup step: unset the env var and verify no drift
				Config:   testKeymgmtAWSKMSConfigNamespace(namespace, mount, kmsName, awsRegion, accessKey, secretKey),
				PlanOnly: true,
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_credentialRotation(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "1"),
					// credentials_wo is write-only and must never appear in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
				),
			},
			{
				Config: testKeymgmtAWSKMSConfigWithVersion(mount, kmsName, awsRegion, accessKey, secretKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "2"),
					// credentials_wo must remain absent from state after credential rotation
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
				),
			},
		},
	})
}

func TestAccKeymgmtAWSKMS_invalidMount(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	awsRegion := testutil.GetTestAWSRegion(t)
	kmsName := acctest.RandomWithPrefix("awskms")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtAWSKMSConfigInvalidMount(kmsName, awsRegion, accessKey, secretKey),
				ExpectError: regexp.MustCompile(".+"),
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

func testKeymgmtAWSKMSConfigNamespace(namespace, mount, kmsName, region, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "keymgmt" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "test" {
  namespace      = vault_namespace.test.path
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}
`, namespace, mount, kmsName, region, accessKey, secretKey)
}

func testKeymgmtAWSKMSConfigWithVersion(mount, kmsName, region, accessKey, secretKey string, version int) string {
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
  credentials_wo_version = %d
}
`, mount, kmsName, region, accessKey, secretKey, version)
}

func testKeymgmtAWSKMSConfigInvalidMount(kmsName, region, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_keymgmt_aws_kms" "test" {
  mount          = "nonexistent-mount"
  name           = %q
  key_collection = %q

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}
`, kmsName, region, accessKey, secretKey)
}
