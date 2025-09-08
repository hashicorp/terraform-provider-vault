// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
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

func TestPkiSecretBackendIntermediateCertRequest_signature_bits(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	testCheckFunc := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", path),
		resource.TestCheckResourceAttr(resourceName, "type", "internal"),
		resource.TestCheckResourceAttr(resourceName, "common_name", "test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.0", "spiffe://test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_signature_bits(path, ""),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSignatureBits),
					assertCsrAttributes(resourceName, x509.SHA256WithRSA),
				)...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_signature_bits(path, "384"),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, consts.FieldSignatureBits, "384"),
					assertCsrAttributes(resourceName, x509.SHA384WithRSA),
				)...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_signature_bits(path, "512"),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, consts.FieldSignatureBits, "512"),
					assertCsrAttributes(resourceName, x509.SHA512WithRSA),
				)...),
			},
		},
	})
}

// assertCsrAttributes so far only checks signature algorithm...
func assertCsrAttributes(resourceName string, expectedSignatureAlgorithm x509.SignatureAlgorithm) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		attrs := rs.Primary.Attributes

		if attrs["format"] != "pem" {
			// assumes that the certificate `format` is `pem`
			return fmt.Errorf("test only valid for resources configured with the 'pem' format")
		}

		csrPEM := attrs["csr"]
		if csrPEM == "" {
			return fmt.Errorf("CSR from state cannot be empty")
		}

		c, _ := pem.Decode([]byte(csrPEM))
		csr, err := x509.ParseCertificateRequest(c.Bytes)
		if err != nil {
			return err
		}

		if expectedSignatureAlgorithm != csr.SignatureAlgorithm {
			return fmt.Errorf("expected signature algorithm (form signature_bits) %s, actual %s", expectedSignatureAlgorithm, csr.SignatureAlgorithm)
		}

		return nil
	}
}

func testPkiSecretBackendIntermediateCertRequestConfig_signature_bits(path string, optionalSignatureBits string) string {
	return testPkiSecretBackendIntermediateCertRequestConfig(path, false, optionalSignatureBits, "", "")
}

func TestPkiSecretBackendIntermediateCertRequest_key_usage(t *testing.T) {
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_key_usage(path, ""),
				Check:  resource.ComposeTestCheckFunc(append(testCheckFunc, resource.TestCheckNoResourceAttr(resourceName, consts.FieldKeyUsage))...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_key_usage(path, `["certsign"]`),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".0", "certsign"))...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_key_usage(path, `["keyagreement", "DecipherOnly"]`),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".0", "keyagreement"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".1", "DecipherOnly"))...),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_key_usage(path string, optionalKeyUsage string) string {
	return testPkiSecretBackendIntermediateCertRequestConfig(path, false, "", optionalKeyUsage, "")
}

func TestPkiSecretBackendIntermediateCertRequest_serial_number(t *testing.T) {
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_serial_number(path, ""),
				Check:  resource.ComposeTestCheckFunc(append(testCheckFunc, resource.TestCheckNoResourceAttr(resourceName, consts.FieldSerialNumber))...),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_serial_number(path, "WI-3005"),
				Check: resource.ComposeTestCheckFunc(append(testCheckFunc,
					resource.TestCheckResourceAttr(resourceName, consts.FieldSerialNumber, "WI-3005"))...),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_serial_number(path string, optionalSerialNumber string) string {
	return testPkiSecretBackendIntermediateCertRequestConfig(path, false, "", "", optionalSerialNumber)
}

func TestPkiSecretBackendIntermediateCertificate_multiIssuer(t *testing.T) {
	path := acctest.RandomWithPrefix("test-pki-mount")

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	keyName := acctest.RandomWithPrefix("test-pki-key")

	// used to test existing key flow
	store := &testPKIKeyStore{}
	keyResourceName := "vault_pki_secret_backend_key.test"
	updatedKeyName := acctest.RandomWithPrefix("test-pki-key-updated")

	commonChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldKeyID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Intermediate CA"),
	}

	internalChecks := append(commonChecks,
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		// keyName is only set on internal if it is passed by user
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
	)

	existingChecks := append(commonChecks,
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "existing"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldKeyRef),
	)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_multiIssuerInternal(path, keyName),
				Check: resource.ComposeTestCheckFunc(
					append(internalChecks)...,
				),
			},
			{
				// Create and capture key ID
				Config: testAccPKISecretBackendKey_basic(path, updatedKeyName, "rsa", "2048"),
				Check: resource.ComposeTestCheckFunc(
					testCapturePKIKeyID(keyResourceName, store),
				),
			},
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_multiIssuerExisting(path, updatedKeyName),
				Check: resource.ComposeTestCheckFunc(
					append(existingChecks,
						// confirm that root cert key ID is same as the key
						// created in step 2; thereby confirming key_ref is passed
						testPKIKeyUpdate(resourceName, store, true),
					)...,
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_basic(path string, addConstraints bool) string {
	return testPkiSecretBackendIntermediateCertRequestConfig(path, addConstraints, "", "", "")
}

func testPkiSecretBackendIntermediateCertRequestConfig(path string, addConstraints bool, optionalSignatureBits, optionalKeyUsage, optionalSerialNumber string) string {
	if optionalSignatureBits != "" {
		optionalSignatureBits = fmt.Sprintf(`signature_bits = "%s"`, optionalSignatureBits)
	}
	if optionalKeyUsage != "" {
		optionalKeyUsage = fmt.Sprintf(`key_usage = %s`, optionalKeyUsage)
	}
	if optionalSerialNumber != "" {
		optionalSerialNumber = fmt.Sprintf(`serial_number = "%s"`, optionalSerialNumber)
	}
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
  %s
  %s
  %s
}
`, path, addConstraints, optionalSignatureBits, optionalKeyUsage, optionalSerialNumber)
}

func testPkiSecretBackendIntermediateCertRequestConfig_multiIssuerInternal(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test Intermediate CA"
  key_name    = "%s"
}
`, path, keyName)
}

func testPkiSecretBackendIntermediateCertRequestConfig_multiIssuerExisting(path, keyName string) string {
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
  key_name = "%s"
  key_type = "rsa"
  key_bits = "2048"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test.path
  type        = "existing"
  common_name = "test Intermediate CA"
  key_ref     = vault_pki_secret_backend_key.test.key_id
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
