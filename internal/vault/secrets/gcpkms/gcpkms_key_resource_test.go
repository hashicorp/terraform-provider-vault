// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

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

func TestGCPKMSSecretBackendKey_basic(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyRing, keyRing),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPurpose, "encrypt_decrypt"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "symmetric_encryption"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProtectionLevel, "software"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "2592000s"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPrimaryVersion),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccGCPKMSSecretBackendKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCryptoKey,
					consts.FieldKeyRing,
				},
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_update(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "2592000s"),
				),
			},
			{
				Config: testGCPKMSSecretBackendKey_updateConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "3600000s"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_withCryptoKey(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	// Use a unique crypto key name to avoid conflicts
	cryptoKeyName := acctest.RandomWithPrefix("crypto-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_cryptoKeyConfig(path, keyName, keyRing, cryptoKeyName, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyRing, keyRing),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCryptoKey, cryptoKeyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPurpose, "encrypt_decrypt"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "symmetric_encryption"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProtectionLevel, "software"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_signingKey(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-sign-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_signingConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyRing, keyRing),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPurpose, "asymmetric_sign"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "rsa_sign_pss_2048_sha256"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_labels(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_labelsConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldLabels+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLabels+".env", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLabels+".managed-by", "terraform"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_validation(t *testing.T) {
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testGCPKMSSecretBackendKey_missingRequiredConfig(path, keyName, credentials),
				ExpectError: regexp.MustCompile(`The argument "key_ring" is required`),
			},
		},
	})
}

func testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  rotation_period  = "2592000s"
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSSecretBackendKey_updateConfig(path, keyName, keyRing, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  rotation_period  = "3600000s"
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSSecretBackendKey_cryptoKeyConfig(path, keyName, keyRing, cryptoKeyName, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials_wo = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  crypto_key       = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}
`, path, credentials, keyName, keyRing, cryptoKeyName)
}

func testGCPKMSSecretBackendKey_signingConfig(path, keyName, keyRing, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "rsa_sign_pss_2048_sha256"
  protection_level = "software"
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSSecretBackendKey_labelsConfig(path, keyName, keyRing, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  labels = {
    env        = "test"
    managed-by = "terraform"
  }
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSSecretBackendKey_conflictConfig(path, keyName, keyRing, cryptoKey, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount      = vault_gcpkms_secret_backend.test.path
  name       = "%s"
  key_ring   = "%s"
  crypto_key = "%s"
  purpose    = "encrypt_decrypt"
  algorithm  = "symmetric_encryption"
}
`, path, credentials, keyName, keyRing, cryptoKey)
}

func testGCPKMSSecretBackendKey_missingRequiredConfig(path, keyName, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount = vault_gcpkms_secret_backend.test.path
  name    = "%s"
  # Missing both key_ring and crypto_key
}
`, path, credentials, keyName)
}

func testAccGCPKMSSecretBackendKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/keys/%s", mount, name), nil
	}
}
