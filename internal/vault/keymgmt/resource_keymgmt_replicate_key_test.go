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
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtReplicateKey(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	sessionToken := testutil.GetTestAWSSessionToken(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_replicate_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtReplicateKeyConfig(backend, kmsName, keyName, accessKey, secretKey, sessionToken),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
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
	sessionToken := testutil.GetTestAWSSessionToken(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtReplicateKeyConfig_NoReplicaRegions(backend, kmsName, keyName, accessKey, secretKey, sessionToken),
				ExpectError: regexp.MustCompile("does not have replica_regions"),
			},
		},
	})
}

func TestAccKeymgmtReplicateKey_multiple(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	sessionToken := testutil.GetTestAWSSessionToken(t)

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
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtReplicateKeyConfigMultiple(backend, kmsName, keyName1, keyName2, accessKey, secretKey, sessionToken),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldKeyName, keyName1),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldKeyName, keyName2),
				),
			},
		},
	})
}

func testKeymgmtReplicateKeyConfig(path, kmsName, keyName, accessKey, secretKey, sessionToken string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  type             = "aes256-gcm96"
  replica_regions  = ["us-east-1", "eu-west-1"]
  deletion_allowed = true
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key    = %q
    secret_key    = %q
    session_token = %q
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
`, path, keyName, kmsName, accessKey, secretKey, sessionToken)
}

func testKeymgmtReplicateKeyConfig_NoReplicaRegions(path, kmsName, keyName, accessKey, secretKey, sessionToken string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  type             = "aes256-gcm96"
  deletion_allowed = true
  # No replica_regions specified
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key    = %q
    secret_key    = %q
    session_token = %q
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
`, path, keyName, kmsName, accessKey, secretKey, sessionToken)
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

func testKeymgmtReplicateKeyConfigMultiple(path, kmsName, keyName1, keyName2, accessKey, secretKey, sessionToken string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  mount            = vault_mount.test.path
  name             = "%s"
  type             = "aes256-gcm96"
  replica_regions  = ["us-east-1", "eu-west-1"]
  deletion_allowed = true
}

resource "vault_keymgmt_key" "test2" {
  mount            = vault_mount.test.path
  name             = "%s"
  type             = "aes256-gcm96"
  replica_regions  = ["ap-southeast-1", "ap-northeast-1"]
  deletion_allowed = true
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key    = %q
    secret_key    = %q
    session_token = %q
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
`, path, keyName1, keyName2, kmsName, accessKey, secretKey, sessionToken)
}
