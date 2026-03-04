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

func TestGCPKMSVerifyDataSource_basic(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_basicConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldDigest),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldSignature),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldValid),
				),
			},
		},
	})
}

func TestGCPKMSVerifyDataSource_withKeyVersion(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_withKeyVersionConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldKeyVersion, "1"),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldValid),
				),
			},
		},
	})
}

func TestGCPKMSVerifyDataSource_invalidSignature(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("test-key")

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_invalidSignatureConfig(path, keyName, keyRing, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldValid, "false"),
				),
			},
		},
	})
}

func TestGCPKMSVerifyDataSource_namespace(t *testing.T) {
	credentials, keyRing := testutil.GetTestGCPKMSCreds(t)

	dataSourceType := "vault_gcpkms_verify"
	dataSourceName := "data." + dataSourceType + ".test"

	getSteps := func(path, keyName, ns string) []resource.TestStep {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttr(dataSourceName, consts.FieldMount, path),
			resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, keyName),
			resource.TestCheckResourceAttr(dataSourceName, consts.FieldKeyVersion, "1"),
			resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldValid),
		}
		if ns != "" {
			checks = append(checks,
				resource.TestCheckResourceAttr(dataSourceName, consts.FieldNamespace, ns),
			)
		}
		return []resource.TestStep{
			{
				Config: testGCPKMSVerifyDataSource_nsConfig(path, keyName, keyRing, credentials, ns),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		}
	}

	t.Run("basic", func(t *testing.T) {
		path := acctest.RandomWithPrefix("tf-test-gcpkms")
		keyName := acctest.RandomWithPrefix("test-key")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			Steps:                    getSteps(path, keyName, ""),
		})
	})

	t.Run("ns", func(t *testing.T) {
		path := acctest.RandomWithPrefix("tf-test-gcpkms")
		keyName := acctest.RandomWithPrefix("test-key")
		ns := acctest.RandomWithPrefix("tf-test-ns")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			Steps:                    getSteps(path, keyName, ns),
		})
	})
}

// testGCPKMSVerifyDataSource_nsConfig generates a config that mounts the backend
// and runs the verify data source inside a specific namespace when ns is non-empty,
// or at root when ns is "".
func testGCPKMSVerifyDataSource_nsConfig(path, keyName, keyRing, credentials, ns string) string {
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
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
%s
}

resource "vault_gcpkms_secret_backend_key" "test" {
  mount            = vault_gcpkms_secret_backend.test.path
  name             = "%s"
  key_ring         = "%s"
  purpose          = "asymmetric_sign"
  algorithm        = "rsa_sign_pss_2048_sha256"
  protection_level = "software"
%s
}

data "vault_gcpkms_verify" "test" {
  mount       = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  key_version = 1
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "dGVzdC1zaWduYXR1cmU="
%s
}
`, nsBlock, path, credentials, namespaceAttr, keyName, keyRing, namespaceAttr, namespaceAttr)
}

func testGCPKMSVerifyDataSource_basicConfig(path, keyName, keyRing, credentials string) string {
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

data "vault_gcpkms_verify" "test" {
  mount       = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  key_version = 1
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "dGVzdC1zaWduYXR1cmU="
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSVerifyDataSource_withKeyVersionConfig(path, keyName, keyRing, credentials string) string {
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

data "vault_gcpkms_verify" "test" {
  mount       = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "dGVzdC1zaWduYXR1cmU="
  key_version = 1
}
`, path, credentials, keyName, keyRing)
}

func testGCPKMSVerifyDataSource_invalidSignatureConfig(path, keyName, keyRing, credentials string) string {
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

data "vault_gcpkms_verify" "test" {
  mount       = vault_gcpkms_secret_backend.test.path
  name        = vault_gcpkms_secret_backend_key.test.name
  key_version = 1
  digest      = "dGVzdC1kaWdlc3Q="
  signature   = "aW52YWxpZC1zaWduYXR1cmU="
}
`, path, credentials, keyName, keyRing)
}
