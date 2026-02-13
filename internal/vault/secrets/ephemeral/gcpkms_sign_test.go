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

// GCP KMS Sign Tests
//
// These tests require actual GCP KMS infrastructure and Vault's GCP KMS secrets engine.
// The sign endpoint is provided by Vault's GCP KMS plugin and requires real connectivity
// to Google Cloud KMS.
//
// To run these tests, set the following environment variables:
// - GOOGLE_CREDENTIALS: GCP service account JSON credentials with KMS permissions
// - GOOGLE_KMS_KEY_RING: Full GCP KMS key ring path (e.g., "projects/my-project/locations/us-central1/keyRings/my-keyring")
//
// Without these environment variables, the tests will be skipped.
//
// Note: These tests create real GCP KMS keys and perform actual signing operations.

func TestAccGCPKMSSign_basic(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	// SHA256 digest of "test message" (base64 encoded)
	digest := "LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
	keyVersion := "1"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSSignConfig(backend, keyName, digest, keyVersion),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(regexpBase64)),
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSSign_differentAlgorithms(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyNameP256 := acctest.RandomWithPrefix("test-key-p256")
	keyNameP384 := acctest.RandomWithPrefix("test-key-p384")

	// SHA256 digest of "test message" (base64 encoded)
	digestSHA256 := "LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
	// SHA384 digest of "test message" (base64 encoded)
	digestSHA384 := "qr3HFcjNg5ac9vH7kIpVTnzfW6VZLxPLlQsYcM3fQJ3VTLI/JZ3wN2a9c8mYgCN4"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSSignWithBothAlgorithmsConfig(backend, keyNameP256, keyNameP384, digestSHA256, digestSHA384, "1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature_p256", tfjsonpath.New("data").AtMapKey("signature_p256").AtMapKey("signature"), knownvalue.StringRegexp(regexpBase64)),
					statecheck.ExpectKnownValue("echo.signature_p256", tfjsonpath.New("data").AtMapKey("signature_p256").AtMapKey("signature"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.signature_p384", tfjsonpath.New("data").AtMapKey("signature_p384").AtMapKey("signature"), knownvalue.StringRegexp(regexpBase64)),
					statecheck.ExpectKnownValue("echo.signature_p384", tfjsonpath.New("data").AtMapKey("signature_p384").AtMapKey("signature"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSSign_differentDigests(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	backend := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	// Different SHA256 digests (base64 encoded)
	digest1 := "LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
	digest2 := "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
	keyVersion := "1"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPKMSSignConfig(backend, keyName, digest1, keyVersion),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(regexpBase64)),
				},
			},
			{
				Config: testAccGCPKMSSignConfig(backend, keyName, digest2, keyVersion),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(regexpBase64)),
				},
			},
		},
	})
}

func testAccGCPKMSSignConfig(backend, keyName, digest, keyVersion string) string {
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
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

ephemeral "vault_gcpkms_sign" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  digest      = "%s"
  key_version = %s
  mount_id    = vault_gcpkms_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_gcpkms_sign.test
}

resource "echo" "signature" {}
`, backend, getMockGCPCredentials(), keyName, getMockKeyRing(), digest, keyVersion)
}

func testAccGCPKMSSignWithBothAlgorithmsConfig(backend, keyNameP256, keyNameP384, digestSHA256, digestSHA384, keyVersion string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = <<-EOT
%s
EOT
}

resource "vault_gcpkms_secret_backend_key" "test_p256" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

resource "vault_gcpkms_secret_backend_key" "test_p384" {
  backend          = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p384_sha384"
  protection_level = "software"
}

ephemeral "vault_gcpkms_sign" "test_p256" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test_p256.name
  digest      = "%s"
  key_version = %s
  mount_id    = vault_gcpkms_secret_backend.test.id
}

ephemeral "vault_gcpkms_sign" "test_p384" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test_p384.name
  digest      = "%s"
  key_version = %s
  mount_id    = vault_gcpkms_secret_backend.test.id
}

provider "echo" {
  data = {
    signature_p256 = ephemeral.vault_gcpkms_sign.test_p256
    signature_p384 = ephemeral.vault_gcpkms_sign.test_p384
  }
}

resource "echo" "signature_p256" {}
resource "echo" "signature_p384" {}
`, backend, getMockGCPCredentials(), keyNameP256, getMockKeyRing(), keyNameP384, getMockKeyRing(), digestSHA256, keyVersion, digestSHA384, keyVersion)
}
