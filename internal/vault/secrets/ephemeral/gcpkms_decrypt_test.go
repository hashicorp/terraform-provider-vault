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

// GCP KMS Decrypt Tests
//
// These tests require actual GCP KMS infrastructure and Vault's GCP KMS secrets engine.
// The operational endpoints (encrypt, decrypt, sign, verify, reencrypt) are provided by
// Vault's GCP KMS plugin and require real connectivity to Google Cloud KMS.
//
// To run these tests, set the following environment variables:
// - GOOGLE_CREDENTIALS: GCP service account JSON credentials with KMS permissions
// - GOOGLE_KMS_KEY_RING: Full GCP KMS key ring path (e.g., "projects/my-project/locations/us-central1/keyRings/my-keyring")
//
// Without these environment variables, the tests will be skipped.
//
// Note: These tests create real GCP KMS keys and perform actual encryption/decryption operations.

func TestAccGCPKMSDecrypt_basic(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSDecryptConfig(backend, keyName, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSDecrypt_withAAD(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSDecryptWithAADConfig(backend, keyName, aad, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpBase64)),
				},
			},
		},
	})
}

func TestAccGCPKMSDecrypt_withKeyVersion(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSDecryptWithKeyVersionConfig(backend, keyName, keyVersion, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpBase64)),
				},
			},
		},
	})
}

func TestAccGCPKMSDecrypt_namespace(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	getSteps := func(backend, keyName, ns, credentials, keyRing string) []resource.TestStep {
		return []resource.TestStep{
			{
				Config: testAccGCPKMSDecryptNsConfig(backend, keyName, ns, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.plaintext", tfjsonpath.New("data").AtMapKey("plaintext"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
				},
			},
		}
	}

	t.Run("basic", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcpkms")
		keyName := acctest.RandomWithPrefix("test-key")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
				"echo": echoprovider.NewProviderServer(),
			},
			Steps: getSteps(backend, keyName, "", credentials, keyRing),
		})
	})

	t.Run("ns", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcpkms")
		keyName := acctest.RandomWithPrefix("test-key")
		ns := acctest.RandomWithPrefix("tf-test-ns")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
				"echo": echoprovider.NewProviderServer(),
			},
			Steps: getSteps(backend, keyName, ns, credentials, keyRing),
		})
	})
}

func testAccGCPKMSDecryptNsConfig(backend, keyName, ns, credentials, keyRing string) string {
	nsBlock := ""
	namespaceAttr := ""
	if ns != "" {
		nsBlock = fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns)
		namespaceAttr = `  namespace = vault_namespace.test.path`
	}

	return fmt.Sprintf(`
%s
resource "vault_mount" "test" {
  path = "%s"
  type = "gcpkms"
%s
}

resource "vault_gcpkms_secret_backend" "test" {
  mount                  = vault_mount.test.path
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
%s
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
%s
}

ephemeral "vault_gcpkms_encrypt" "test" {
  mount_id  = vault_mount.test.id
  mount     = vault_mount.test.path
  name      = vault_gcpkms_secret_backend_key.test.name
  plaintext = base64encode("test plaintext data")
%s
}

ephemeral "vault_gcpkms_decrypt" "test" {
  mount      = vault_mount.test.path
  name       = vault_gcpkms_secret_backend_key.test.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.test.ciphertext
%s
}

provider "echo" {
  data = ephemeral.vault_gcpkms_decrypt.test
}

resource "echo" "plaintext" {}
`, nsBlock, backend, namespaceAttr, credentials, namespaceAttr, keyName, keyRing, namespaceAttr, namespaceAttr, namespaceAttr)
}

func testAccGCPKMSDecryptConfig(backend, keyName, credentials, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "test" {
  mount                  = vault_mount.test.path
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}

# First encrypt some data
ephemeral "vault_gcpkms_encrypt" "test" {
  mount_id  = vault_mount.test.id
  mount     = vault_mount.test.path
  name      = vault_gcpkms_secret_backend_key.test.name
  plaintext = base64encode("test plaintext data")
}

# Then decrypt it
ephemeral "vault_gcpkms_decrypt" "test" {
  mount      = vault_mount.test.path
  name       = vault_gcpkms_secret_backend_key.test.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.test.ciphertext
}

provider "echo" {
  data = ephemeral.vault_gcpkms_decrypt.test
}

resource "echo" "plaintext" {}
`, backend, credentials, keyName, keyRing)
}

func testAccGCPKMSDecryptWithAADConfig(backend, keyName, aad, credentials, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "test" {
  mount                  = vault_mount.test.path
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}

# First encrypt data with AAD
ephemeral "vault_gcpkms_encrypt" "test" {
  mount_id                      = vault_mount.test.id
  mount                         = vault_mount.test.path
  name                          = vault_gcpkms_secret_backend_key.test.name
  plaintext                     = base64encode("test plaintext with AAD")
  additional_authenticated_data = "%s"
}

# Then decrypt it with the same AAD
ephemeral "vault_gcpkms_decrypt" "test" {
  mount                         = vault_mount.test.path
  name                          = vault_gcpkms_secret_backend_key.test.name
  ciphertext                    = ephemeral.vault_gcpkms_encrypt.test.ciphertext
  additional_authenticated_data = "%s"
}

provider "echo" {
  data = ephemeral.vault_gcpkms_decrypt.test
}

resource "echo" "plaintext" {}
`, backend, credentials, keyName, keyRing, aad, aad)
}

func testAccGCPKMSDecryptWithKeyVersionConfig(backend, keyName, keyVersion, credentials, keyRing string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "test" {
  mount                  = vault_mount.test.path
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}

# First encrypt data with specific key version
ephemeral "vault_gcpkms_encrypt" "test" {
  mount_id    = vault_mount.test.id
  mount       = vault_mount.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  plaintext   = base64encode("test plaintext for key version")
  key_version = %s
}

# Then decrypt it (key version is determined from the ciphertext)
ephemeral "vault_gcpkms_decrypt" "test" {
  mount      = vault_mount.test.path
  name       = vault_gcpkms_secret_backend_key.test.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.test.ciphertext
}

provider "echo" {
  data = ephemeral.vault_gcpkms_decrypt.test
}

resource "echo" "plaintext" {}
`, backend, credentials, keyName, keyRing, keyVersion)
}
