// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// GCP KMS Reencrypt Tests
//
// These tests require actual GCP KMS infrastructure and Vault's GCP KMS secrets engine.
// The reencrypt endpoint is provided by Vault's GCP KMS plugin and requires real connectivity
// to Google Cloud KMS.
//
// To run these tests, set the following environment variables:
// - GOOGLE_CREDENTIALS: GCP service account JSON credentials with KMS permissions
// - GOOGLE_KMS_KEY_RING: Full GCP KMS key ring path (e.g., "projects/my-project/locations/us-central1/keyRings/my-keyring")
//
// Without these environment variables, the tests will be skipped.
//
// Note: These tests create real GCP KMS keys and perform actual reencryption operations,
// which may incur GCP costs.

func TestAccGCPKMSReencrypt_basic(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSReencryptConfig(backend, keyName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.new_ciphertext", tfjsonpath.New("data").AtMapKey("new_ciphertext"), knownvalue.StringRegexp(regexpBase64)),
					statecheck.ExpectKnownValue("echo.new_ciphertext", tfjsonpath.New("data").AtMapKey("new_ciphertext"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSReencrypt_withAAD(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	aad := "dGVzdC1hYWQ="

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSReencryptWithAADConfig(backend, keyName, aad),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.new_ciphertext", tfjsonpath.New("data").AtMapKey("new_ciphertext"), knownvalue.StringRegexp(regexpBase64)),
				},
			},
		},
	})
}

func TestAccGCPKMSReencrypt_withKeyVersion(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyVersion := "1"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSReencryptWithKeyVersionConfig(backend, keyName, keyVersion),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.new_ciphertext", tfjsonpath.New("data").AtMapKey("new_ciphertext"), knownvalue.StringRegexp(regexpBase64)),
				},
			},
		},
	})
}

func testAccGCPKMSReencryptConfig(backend, keyName string) string {
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
}

# First encrypt some data to get a real ciphertext
ephemeral "vault_gcpkms_encrypt" "test" {
  backend   = vault_gcpkms_secret_backend.test.path
  name      = vault_gcpkms_secret_backend_key.test.name
  plaintext = base64encode("test plaintext data")
  mount_id  = vault_gcpkms_secret_backend.test.id
}

# Then reencrypt it
ephemeral "vault_gcpkms_reencrypt" "test" {
  backend    = vault_gcpkms_secret_backend.test.path
  name       = vault_gcpkms_secret_backend_key.test.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.test.ciphertext
  mount_id   = vault_gcpkms_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_gcpkms_reencrypt.test
}

resource "echo" "new_ciphertext" {}
`, backend, getMockGCPCredentials(), keyName, getMockKeyRing())
}

func testAccGCPKMSReencryptWithAADConfig(backend, keyName, aad string) string {
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
}

# First encrypt data with AAD
ephemeral "vault_gcpkms_encrypt" "test" {
  backend                       = vault_gcpkms_secret_backend.test.path
  name                          = vault_gcpkms_secret_backend_key.test.name
  plaintext                     = base64encode("test plaintext with AAD")
  additional_authenticated_data = "%s"
  mount_id                      = vault_gcpkms_secret_backend.test.id
}

# Then reencrypt it with the same AAD
ephemeral "vault_gcpkms_reencrypt" "test" {
  backend                       = vault_gcpkms_secret_backend.test.path
  name                          = vault_gcpkms_secret_backend_key.test.name
  ciphertext                    = ephemeral.vault_gcpkms_encrypt.test.ciphertext
  additional_authenticated_data = "%s"
  mount_id                      = vault_gcpkms_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_gcpkms_reencrypt.test
}

resource "echo" "new_ciphertext" {}
`, backend, getMockGCPCredentials(), keyName, getMockKeyRing(), aad, aad)
}

func testAccGCPKMSReencryptWithKeyVersionConfig(backend, keyName, keyVersion string) string {
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
}

# First encrypt data with specific key version
ephemeral "vault_gcpkms_encrypt" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  plaintext   = base64encode("test plaintext for key version")
  key_version = %s
  mount_id    = vault_gcpkms_secret_backend.test.id
}

# Then reencrypt it to a different key version
ephemeral "vault_gcpkms_reencrypt" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  ciphertext  = ephemeral.vault_gcpkms_encrypt.test.ciphertext
  key_version = %s
  mount_id    = vault_gcpkms_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_gcpkms_reencrypt.test
}

resource "echo" "new_ciphertext" {}
`, backend, getMockGCPCredentials(), keyName, getMockKeyRing(), keyVersion, keyVersion)
}
