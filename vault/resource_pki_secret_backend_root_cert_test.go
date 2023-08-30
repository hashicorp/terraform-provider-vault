// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRootCertificate_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_root_cert.test"

	store := &testPKICertStore{}

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "86400"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldFormat, "pem"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyFormat, "der"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "4096"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOu, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCountry, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocality, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldProvince, "test"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerial),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootCertificateConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
			{
				// test unmounted backend
				PreConfig: func() {
					client, err := provider.GetClient("", testProvider.Meta())
					if err != nil {
						t.Fatal(err)
					}

					if err := client.Sys().Unmount(path); err != nil {
						t.Fatal(err)
					}
				},
				Config: testPkiSecretBackendRootCertificateConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, store),
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
			{
				// test out of band update to the root CA
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

					_, err := client.Logical().Delete(fmt.Sprintf("%s/root", path))
					if err != nil {
						t.Fatal(err)
					}

					isMultiIssuerSupported := testProvider.Meta().(*provider.ProviderMeta).IsAPISupported(provider.VaultVersion111)
					genPath := pkiSecretBackendGenerateRootPath(path, "internal", isMultiIssuerSupported)
					resp, err := client.Logical().Write(genPath,
						map[string]interface{}{
							consts.FieldCommonName: "out-of-band",
						},
					)
					if err != nil {
						t.Fatal(err)
					}

					if resp == nil {
						t.Fatalf("empty response for write on path %s", genPath)
					}
				},
				Config: testPkiSecretBackendRootCertificateConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, store),
					)...,
				),
			},
		},
	})
}

func TestPkiSecretBackendRootCertificate_multiIssuer(t *testing.T) {
	path := acctest.RandomWithPrefix("test-pki-mount")

	resourceName := "vault_pki_secret_backend_root_cert.test"
	keyName := acctest.RandomWithPrefix("test-pki-key")
	issuerName := acctest.RandomWithPrefix("test-pki-issuer")

	// used to test existing key flow
	store := &testPKIKeyStore{}
	keyResourceName := "vault_pki_secret_backend_key.test"
	updatedKeyName := acctest.RandomWithPrefix("test-pki-key-updated")

	commonChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldKeyID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
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
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootCertificateConfig_multiIssuerInternal(path, issuerName, keyName),
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
				Config: testPkiSecretBackendRootCertificateConfig_multiIssuerExisting(path, issuerName, updatedKeyName),
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

// Ensures that TF state is cleanly resolved whenever
// multiple root certs are generated
func TestAccPKISecretBackendRootCert_multipleRootCerts(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_root_cert"
	resourceCurrentIssuer := resourceType + ".current"
	resourceNextIssuer := resourceType + ".next"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendRootCert_multipleRootCerts(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceCurrentIssuer, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceCurrentIssuer, consts.FieldType, "internal"),
					resource.TestCheckResourceAttrSet(resourceCurrentIssuer, consts.FieldIssuerID),

					resource.TestCheckResourceAttr(resourceNextIssuer, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceNextIssuer, consts.FieldType, "internal"),
					resource.TestCheckResourceAttrSet(resourceNextIssuer, consts.FieldIssuerID),
				),
			},
		},
	})
}

func TestPkiSecretBackendRootCertificate_managedKeys(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_root_cert.test"
	managedKeyName := acctest.RandomWithPrefix("kms-key")

	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "kms"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldManagedKeyName, managedKeyName),
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootCertificateConfig_managedKeys(path, managedKeyName, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					append(checks)...,
				),
			},
		},
	})
}

func testPkiSecretBackendRootCertificateConfig_basic(path string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test.path
  type                 = "internal"
  common_name          = "test Root CA"
  ttl                  = "86400"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "test"
  organization         = "test"
  country              = "test"
  locality             = "test"
  province             = "test"
}
`, path)

	return config
}

func testPkiSecretBackendRootCertificateConfig_multiIssuerInternal(path, issuer, key string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test.path
  type                 = "internal"
  common_name          = "test Root CA"
  issuer_name          = "%s"
  key_name             = "%s"
}
`, path, issuer, key)

	return config
}

func testPkiSecretBackendRootCertificateConfig_multiIssuerExisting(path, issuer, key string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_key" "test" {
  backend  = vault_mount.test.path
  type     = "exported"
  key_name = "%s"
  key_type = "rsa"
  key_bits = "2048"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test.path
  type                 = "existing"
  common_name          = "test Root CA"
  issuer_name          = "%s"
  key_ref              = vault_pki_secret_backend_key.test.key_id
}
`, path, key, issuer)

	return config
}

func testAccPKISecretBackendRootCert_multipleRootCerts(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
	description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_root_cert" "current" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_root_cert" "next" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}`, path)
}

func testPkiSecretBackendRootCertificateConfig_managedKeys(path, managedKeyName, accessKey, secretKey string) string {
	config := fmt.Sprintf(`
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
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
  allowed_managed_keys      = [tolist(vault_managed_keys.test.aws)[0].name]
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend          = vault_mount.test.path
  type             = "kms"
  common_name      = "test Root CA"
  managed_key_id = tolist(vault_managed_keys.test.aws)[0].uuid
}
`, managedKeyName, accessKey, secretKey, path)

	return config
}

func Test_pkiSecretSerialNumberUpgradeV0(t *testing.T) {
	tests := []struct {
		name     string
		rawState map[string]interface{}
		want     map[string]interface{}
		wantErr  bool
	}{
		{
			name: "basic",
			rawState: map[string]interface{}{
				consts.FieldSerial: "aa:bb:cc:dd:ee",
			},
			want: map[string]interface{}{
				consts.FieldSerial:       "aa:bb:cc:dd:ee",
				consts.FieldSerialNumber: "aa:bb:cc:dd:ee",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkiSecretSerialNumberUpgradeV0(nil, tt.rawState, nil)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("pkiSecretSerialNumberUpgradeV0() error = %#v, wantErr %#v", err, tt.wantErr)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkiSecretSerialNumberUpgradeV0() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}
