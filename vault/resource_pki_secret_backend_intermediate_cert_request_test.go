// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendIntermediateCertRequest_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	testCheckFunc := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", path),
		resource.TestCheckResourceAttr(resourceName, "type", "internal"),
		resource.TestCheckResourceAttr(resourceName, "common_name", "test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.0", "spiffe://test.my.domain"),
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_basic(path, false),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, "add_basic_constraints", "false"))...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_basic(path, true),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, "add_basic_constraints", "true"))...),
			},
		},
	})
}

func TestPkiSecretBackendIntermediateCertRequest_managedKeys(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	keyName := acctest.RandomWithPrefix("kms-key")

	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_managedKeys(path, keyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", path),
					resource.TestCheckResourceAttr(resourceName, "type", "kms"),
					resource.TestCheckResourceAttr(resourceName, "common_name", "test.my.domain"),
					resource.TestCheckResourceAttr(resourceName, "uri_sans.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "uri_sans.0", "spiffe://test.my.domain"),
					resource.TestCheckResourceAttr(resourceName, "managed_key_name", keyName),
				),
			},
		},
	})
}

func TestPkiSecretBackendIntermediateCertificate_multiIssuer(t *testing.T) {
	path := acctest.RandomWithPrefix("test-pki-mount")

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	keyName := acctest.RandomWithPrefix("test-pki-key")

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Intermediate CA"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldKeyID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldKeyRef),
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			// @TODO add a test step with a key_ref
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_multiIssuer(path, keyName),
				Check: resource.ComposeTestCheckFunc(
					append(checks)...,
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_basic(path string, addConstraints bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend               = vault_mount.test.path
  type                  = "internal"
  common_name           = "test.my.domain"
  uri_sans              = ["spiffe://test.my.domain"]
  add_basic_constraints = %t
}
`, path, addConstraints)
}

func testPkiSecretBackendIntermediateCertRequestConfig_multiIssuer(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_key" "test" {
  backend  = vault_mount.test.path
  type     = "exported"
  key_name = "test"
  key_type = "rsa"
  key_bits = "4096"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test Intermediate CA"
  key_ref     = vault_pki_secret_backend_key.test.id
  key_name    = "%s"
}
`, path, keyName)
}

func testPkiSecretBackendIntermediateCertRequestConfig_managedKeys(path, keyName, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  aws {
    name       = "%s"
    access_key = "%s"
    secret_key = "%s"
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string"
  }
}

resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
  allowed_managed_keys      = [tolist(vault_managed_keys.test.aws)[0].name]
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend          = vault_mount.test.path
  type             = "kms"
  managed_key_name = tolist(vault_managed_keys.test.aws)[0].name
  common_name      = "test.my.domain"
  uri_sans         = ["spiffe://test.my.domain"]
}
`, keyName, accessKey, secretKey, path)
}
