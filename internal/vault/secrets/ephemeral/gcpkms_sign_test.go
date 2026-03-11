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
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSSignConfig(backend, keyName, digest, keyVersion, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSSign_differentAlgorithms(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSSignWithBothAlgorithmsConfig(backend, keyNameP256, keyNameP384, digestSHA256, digestSHA384, "1", credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature_p256", tfjsonpath.New("data").AtMapKey("signature_p256").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.signature_p256", tfjsonpath.New("data").AtMapKey("signature_p256").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.signature_p384", tfjsonpath.New("data").AtMapKey("signature_p384").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.signature_p384", tfjsonpath.New("data").AtMapKey("signature_p384").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
				},
			},
		},
	})
}

func TestAccGCPKMSSign_differentDigests(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

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
				Config: testAccGCPKMSSignConfig(backend, keyName, digest1, keyVersion, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
				},
			},
			{
				Config: testAccGCPKMSSignConfig(backend, keyName, digest2, keyVersion, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
				},
			},
		},
	})
}

func TestAccGCPKMSSign_namespace(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	digest := "LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
	keyVersion := "1"

	getSteps := func(backend, keyName, ns, credentials, keyRing string) []resource.TestStep {
		return []resource.TestStep{
			{
				Config: testAccGCPKMSSignNsConfig(backend, keyName, digest, keyVersion, ns, credentials, keyRing),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpBase64)),
					statecheck.ExpectKnownValue("echo.signature", tfjsonpath.New("data").AtMapKey("signature"), knownvalue.StringRegexp(testutil.RegexpNonEmpty)),
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

func testAccGCPKMSSignNsConfig(backend, keyName, digest, keyVersion, ns, credentials, keyRing string) string {
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
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
%s
}

ephemeral "vault_gcpkms_sign" "test" {
  mount_id    = vault_mount.test.id
  mount       = vault_mount.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  digest      = "%s"
  key_version = %s
%s
}

provider "echo" {
  data = ephemeral.vault_gcpkms_sign.test
}

resource "echo" "signature" {}
`, nsBlock, backend, namespaceAttr, credentials, namespaceAttr, keyName, keyRing, namespaceAttr, digest, keyVersion, namespaceAttr)
}

func testAccGCPKMSSignConfig(backend, keyName, digest, keyVersion, credentials, keyRing string) string {
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
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

ephemeral "vault_gcpkms_sign" "test" {
  mount_id    = vault_mount.test.id
  mount       = vault_mount.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  digest      = "%s"
  key_version = %s
}

provider "echo" {
  data = ephemeral.vault_gcpkms_sign.test
}

resource "echo" "signature" {}
`, backend, credentials, keyName, keyRing, digest, keyVersion)
}

func testAccGCPKMSSignWithBothAlgorithmsConfig(backend, keyNameP256, keyNameP384, digestSHA256, digestSHA384, keyVersion, credentials, keyRing string) string {
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

resource "vault_gcpkms_secret_backend_key" "test_p256" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

resource "vault_gcpkms_secret_backend_key" "test_p384" {
  mount            = vault_mount.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p384_sha384"
  protection_level = "software"
}

ephemeral "vault_gcpkms_sign" "test_p256" {
  mount_id    = vault_mount.test.id
  mount       = vault_mount.test.path
  name        = vault_gcpkms_secret_backend_key.test_p256.name
  digest      = "%s"
  key_version = %s
}

ephemeral "vault_gcpkms_sign" "test_p384" {
  mount_id    = vault_mount.test.id
  mount       = vault_mount.test.path
  name        = vault_gcpkms_secret_backend_key.test_p384.name
  digest      = "%s"
  key_version = %s
}

provider "echo" {
  data = {
    signature_p256 = ephemeral.vault_gcpkms_sign.test_p256
    signature_p384 = ephemeral.vault_gcpkms_sign.test_p384
  }
}

resource "echo" "signature_p256" {}
resource "echo" "signature_p384" {}
`, backend, credentials, keyNameP256, keyRing, keyNameP384, keyRing, digestSHA256, keyVersion, digestSHA384, keyVersion)
}
