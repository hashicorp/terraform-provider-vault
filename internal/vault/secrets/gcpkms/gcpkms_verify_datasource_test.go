// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// Note: These tests use environment variables defined in gcpkms_key_resource_test.go:
// - GOOGLE_CREDENTIALS: GCP service account JSON
// - GOOGLE_KMS_KEY_RING: GCP KMS key ring path

func TestGCPKMSVerifyDataSource_basic(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_basicConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldDigest),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldSignature),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldValid),
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
				),
			},
		},
	})
}

func TestGCPKMSVerifyDataSource_withKeyVersion(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_withKeyVersionConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldKeyVersion, "1"),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldValid),
				),
			},
		},
	})
}

func TestGCPKMSVerifyDataSource_invalidSignature(t *testing.T) {
	// Skip if environment variables are not set
	testutil.SkipTestEnvUnset(t, envVarGoogleCredentials, envVarGoogleKMSKeyRing)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")
	keyRing := getMockKeyRing()

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_invalidSignatureConfig(path, keyName, keyRing),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldValid, "false"),
				),
			},
		},
	})
}

func testGCPKMSVerifyDataSource_basicConfig(path, keyName, keyRing string) string {
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

data "vault_gcpkms_verify" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  key_version = 1
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "dGVzdC1zaWduYXR1cmU="
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSVerifyDataSource_withKeyVersionConfig(path, keyName, keyRing string) string {
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

data "vault_gcpkms_verify" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "dGVzdC1zaWduYXR1cmU="
  key_version = 1
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}

func testGCPKMSVerifyDataSource_invalidSignatureConfig(path, keyName, keyRing string) string {
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

data "vault_gcpkms_verify" "test" {
  backend     = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  key_version = 1
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "aW52YWxpZC1zaWduYXR1cmU="
}
`, path, getMockGCPCredentials(), keyName, keyRing)
}
