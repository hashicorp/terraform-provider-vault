// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtReplicateKey(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_replicate_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtReplicateKeyConfig(backend, kmsName, keyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtReplicateKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func TestAccKeymgmtReplicateKey_NoReplicaRegions(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtReplicateKeyConfig_NoReplicaRegions(backend, kmsName, keyName, accessKey, secretKey),
				ExpectError: regexp.MustCompile("replica_regions must be configured"),
			},
		},
	})
}

func TestAccKeymgmtReplicateKey_multiple(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName1 := acctest.RandomWithPrefix("test-key1")
	keyName2 := acctest.RandomWithPrefix("test-key2")

	resourceName1 := "vault_keymgmt_replicate_key.test1"
	resourceName2 := "vault_keymgmt_replicate_key.test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtReplicateKeyConfigMultiple(backend, kmsName, keyName1, keyName2, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName1, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName1, "key_name", keyName1),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName2, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName2, "key_name", keyName2),
				),
			},
		},
	})
}

func testKeymgmtReplicateKeyConfig(path, kmsName, keyName, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  type            = "aes256-gcm96"
  replica_regions = ["us-east-1", "eu-west-1"]
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = %q
    secret_key = %q
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_replicate_key" "test" {
  mount    = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test.name

  depends_on = [vault_keymgmt_distribute_key.test]
}
`, path, keyName, kmsName, accessKey, secretKey)
}

func testKeymgmtReplicateKeyConfig_NoReplicaRegions(path, kmsName, keyName, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
  # No replica_regions specified
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = %q
    secret_key = %q
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_replicate_key" "test" {
  mount    = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test.name

  depends_on = [vault_keymgmt_distribute_key.test]
}
`, path, keyName, kmsName, accessKey, secretKey)
}

func testAccKeymgmtReplicateKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		kmsName := rs.Primary.Attributes["kms_name"]
		keyName := rs.Primary.Attributes["key_name"]
		return fmt.Sprintf("%s/kms/%s/key/%s/replicate", mount, kmsName, keyName), nil
	}
}

func testKeymgmtReplicateKeyConfigMultiple(path, kmsName, keyName1, keyName2, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  mount           = vault_mount.test.path
  name            = "%s"
  type            = "aes256-gcm96"
  replica_regions = ["us-east-1", "eu-west-1"]
}

resource "vault_keymgmt_key" "test2" {
  mount           = vault_mount.test.path
  name            = "%s"
  type            = "aes256-gcm96"
  replica_regions = ["ap-southeast-1", "ap-northeast-1"]
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = %q
    secret_key = %q
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test1" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test1.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_distribute_key" "test2" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test2.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_replicate_key" "test1" {
  mount    = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test1.name
  
  depends_on = [vault_keymgmt_distribute_key.test1]
}

resource "vault_keymgmt_replicate_key" "test2" {
  mount    = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test2.name
  
  depends_on = [vault_keymgmt_distribute_key.test2]
}
`, path, keyName1, keyName2, kmsName, accessKey, secretKey)
}
