// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPKMSSecretBackendKey_basic(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyRing, keyRing),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPurpose, "encrypt_decrypt"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "symmetric_encryption"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProtectionLevel, "software"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "2592000s"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPrimaryVersion),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCryptoKey,
				consts.FieldKeyRing, // key_ring is not returned by Vault API after import
			),
		},
	})
}

func TestGCPKMSSecretBackendKey_update(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "2592000s"),
				),
			},
			{
				Config: testGCPKMSSecretBackendKey_updateConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "3600000s"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackendKey_withCryptoKey(t *testing.T) {
	// Test using a custom crypto_key name instead of defaulting to the Vault key name
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()
	// Use a unique crypto key name to avoid conflicts
	cryptoKeyName := acctest.RandomWithPrefix("crypto-key")

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_cryptoKeyConfig(path, keyName, keyRing, cryptoKeyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
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
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-sign-key")
	keyRing := getMockKeyRing()

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_signingConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
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
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	resourceType := "vault_gcpkms_secret_backend_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackendKey_labelsConfig(path, keyName, keyRing),
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
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testGCPKMSSecretBackendKey_missingRequiredConfig(path, keyName),
				ExpectError: regexp.MustCompile(`The argument "key_ring" is required`),
			},
		},
	})
}

func testGCPKMSSecretBackendKey_initialConfig(path, keyName, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  rotation_period  = "2592000s"
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSSecretBackendKey_updateConfig(path, keyName, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  rotation_period  = "3600000s"
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSSecretBackendKey_cryptoKeyConfig(path, keyName, keyRing, cryptoKeyName string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  crypto_key       = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}
`, path, getMockGCPCredentials(), keyName, keyRing, cryptoKeyName)
}

func testGCPKMSSecretBackendKey_signingConfig(path, keyName, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "rsa_sign_pss_2048_sha256"
  protection_level = "software"
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSSecretBackendKey_labelsConfig(path, keyName, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend          = vault_gcpkms_secret_backend.test.path
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
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSSecretBackendKey_missingRequiredConfig(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test" {
  backend = vault_gcpkms_secret_backend.test.path
  name    = "%s"
  # Missing key_ring
}
`, path, getMockGCPCredentials(), keyName)
}
