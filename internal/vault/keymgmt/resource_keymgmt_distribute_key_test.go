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
	sessionToken := testutil.GetTestAWSSessionToken(t)

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
				Config: testKeymgmtDistributeKeyConfig(backend, kmsName, keyName, accessKey, secretKey, sessionToken),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPurpose+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "decrypt"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProtection, "hsm"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldVersions+"."+"%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldPurpose, consts.FieldProtection},
			},
		},
	})
}

func TestAccKeymgmtDistributeKey_multiple(t *testing.T) {
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	sessionToken := testutil.GetTestAWSSessionToken(t)

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
				Config: testKeymgmtDistributeKeyConfigMultiple(backend, kmsName, keyName1, keyName2, accessKey, secretKey, sessionToken),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldKeyName, keyName1),
					resource.TestCheckResourceAttrSet(resourceName1, consts.FieldVersions+"."+"%"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldKeyName, keyName2),
					resource.TestCheckResourceAttrSet(resourceName2, consts.FieldVersions+"."+"%"),
				),
			},
		},
	})
}

func testKeymgmtDistributeKeyConfig(path, kmsName, keyName, accessKey, secretKey, sessionToken string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key    = "%s"
    secret_key    = "%s"
    session_token = "%s"
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
`, path, keyName, kmsName, accessKey, secretKey, sessionToken)
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

func testKeymgmtDistributeKeyConfigMultiple(path, kmsName, keyName1, keyName2, accessKey, secretKey, sessionToken string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key" "test2" {
  mount = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_aws_kms" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"

  credentials_wo = {
    access_key    = "%s"
    secret_key    = "%s"
    session_token = "%s"
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
`, path, keyName1, keyName2, kmsName, accessKey, secretKey, sessionToken)
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "sign"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "verify"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldVersions+"."+"%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount, ImportStateVerifyIgnore: []string{consts.FieldPurpose, consts.FieldProtection}},
		},
	})
}

func TestAccKeymgmtDistributeKey_gcp(t *testing.T) {
	gcpCredentials := testutil.GetTestGCPCredsFile(t)
	gcpProject := testutil.GetTestGCPProject(t)
	gcpLocation := testutil.GetTestGCPRegion(t)
	gcpKeyRing := testutil.GetTestGCPKeyRing(t)

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
					resource.TestCheckResourceAttr(resourceName, consts.FieldKMSName, kmsName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPurpose+".*", "decrypt"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldVersions+"."+"%"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtDistributeKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldPurpose, consts.FieldProtection},
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
  deletion_allowed = true
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
  deletion_allowed = true
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
