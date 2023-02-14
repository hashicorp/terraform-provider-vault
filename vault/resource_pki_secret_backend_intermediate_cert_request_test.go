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
