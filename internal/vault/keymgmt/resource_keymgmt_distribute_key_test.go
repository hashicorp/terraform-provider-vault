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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtDistributeKey(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfig(backend, kmsName, keyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceName, "purpose.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "decrypt"),
					resource.TestCheckResourceAttr(resourceName, "protection", "hsm"),
					resource.TestCheckResourceAttrSet(resourceName, "versions.%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func TestAccKeymgmtDistributeKey_update(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfig(backend, kmsName, keyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "purpose.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "decrypt"),
				),
			},
			{
				Config: testKeymgmtDistributeKeyConfigWithSign(backend, kmsName, keyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "purpose.#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "decrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "sign"),
				),
			},
		},
	})
}

func TestAccKeymgmtDistributeKey_multiple(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName1 := acctest.RandomWithPrefix("test-key1")
	keyName2 := acctest.RandomWithPrefix("test-key2")

	resourceName1 := "vault_keymgmt_distribute_key.test1"
	resourceName2 := "vault_keymgmt_distribute_key.test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfigMultiple(backend, kmsName, keyName1, keyName2, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName1, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName1, "key_name", keyName1),
					resource.TestCheckResourceAttrSet(resourceName1, "versions.%"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName2, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName2, "key_name", keyName2),
					resource.TestCheckResourceAttrSet(resourceName2, "versions.%"),
				),
			},
		},
	})
}

func testKeymgmtDistributeKeyConfig(path, kmsName, keyName, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
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
`, path, keyName, kmsName, accessKey, secretKey)
}

func testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		kmsName := rs.Primary.Attributes["kms_name"]
		keyName := rs.Primary.Attributes["key_name"]
		return fmt.Sprintf("%s/kms/%s/key/%s", mount, kmsName, keyName), nil
	}
}

func testKeymgmtDistributeKeyConfigWithSign(path, kmsName, keyName, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt", "sign"]
  protection = "hsm"
}
`, path, keyName, kmsName, accessKey, secretKey)
}

func testKeymgmtDistributeKeyConfigMultiple(path, kmsName, keyName1, keyName2, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_key" "test2" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key = "%s"
    secret_key = "%s"
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
`, path, keyName1, keyName2, kmsName, accessKey, secretKey)
}

func TestAccKeymgmtDistributeKey_azure(t *testing.T) {
	tenantID, clientID, clientSecret, keyVaultName := testutil.GetTestAzureKMSCreds(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfigAzure(backend, kmsName, keyName, keyVaultName, tenantID, clientID, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "sign"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "verify"),
					resource.TestCheckResourceAttrSet(resourceName, "versions.%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func TestAccKeymgmtDistributeKey_gcp(t *testing.T) {
	gcpCredentials, gcpProject := testutil.GetTestGCPCreds(t)
	gcpLocation, gcpKeyRing := testutil.GetTestGCPKMSConfig(t)

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyCollection := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", gcpProject, gcpLocation, gcpKeyRing)

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfigGCP(backend, kmsName, keyName, keyCollection, gcpProject, gcpLocation, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "decrypt"),
					resource.TestCheckResourceAttrSet(resourceName, "versions.%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func testKeymgmtDistributeKeyConfigAzure(path, kmsName, keyName, keyVaultName, tenantID, clientID, clientSecret string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name  = %q
  type  = "rsa-2048"
}

resource "vault_keymgmt_azure_kms" "test" {
  mount          = vault_mount.test.path
  name           = %q
  key_collection = %q

  credentials_wo = {
    tenant_id     = %q
    client_id     = %q
    client_secret = %q
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test" {
  mount    = vault_mount.test.path
  kms_name = vault_keymgmt_azure_kms.test.name
  key_name = vault_keymgmt_key.test.name
  purpose  = ["sign", "verify"]
}
`, path, keyName, kmsName, keyVaultName, tenantID, clientID, clientSecret)
}

func testKeymgmtDistributeKeyConfigGCP(path, kmsName, keyName, keyCollection, gcpProject, gcpLocation, gcpCredentials string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name  = %q
  type  = "aes256-gcm96"
}

resource "vault_keymgmt_gcp_kms" "test" {
  mount          = vault_mount.test.path
  name           = %q
  key_collection = %q

  credentials_wo = {
    service_account_file = %q
    project              = %q
    location             = %q
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_distribute_key" "test" {
  mount      = vault_mount.test.path
  kms_name   = vault_keymgmt_gcp_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "software"
}
`, path, keyName, kmsName, keyCollection, gcpCredentials, gcpProject, gcpLocation)
}
