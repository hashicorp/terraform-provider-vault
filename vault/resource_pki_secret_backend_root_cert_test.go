// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRootCertificate_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	config := testPkiSecretBackendRootCertificateConfig_basic(path, "ttl = 86400")
	resourceName := "vault_pki_secret_backend_root_cert.test"
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "86400"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldFormat, "pem"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyFormat, "der"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "4096"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldSignatureBits, "512"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOu, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCountry, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocality, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldProvince, "test"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateAttributes(resourceName, "", x509.SHA512WithRSA),
		// Validate default key usages when key_usage is not explicitly specified
		// Per Vault API docs: default key_usage for root certs is ["CertSign", "CRLSign"]
		assertCertificateKeyUsage(resourceName, []string{"CertSign", "CRLSign"}),
	}

	testPkiSecretBackendRootCertificate(t, path, config, resourceName, checks, nil)
}

func TestPkiSecretBackendRootCertificate_notAfter(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_root_cert.test"
	notAfterTime := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	// setting both not_after and not_before_duration to verify fields work as expected
	config := testPkiSecretBackendRootCertificateConfig_basic(path, fmt.Sprintf("not_after = \"%s\" \n not_before_duration = \"%s\"", notAfterTime, "120s"))

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldFormat, "pem"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyFormat, "der"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "4096"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldSignatureBits, "512"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOu, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCountry, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocality, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldProvince, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNotAfter, notAfterTime),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNotBeforeDuration, "120s"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateAttributes(resourceName, notAfterTime, x509.SHA512WithRSA),
	}

	testPkiSecretBackendRootCertificate(t, path, config, resourceName, checks, nil)
}

// TestPkiSecretBackendRootCertificate_usePSS tests the use_pss field
func TestPkiSecretBackendRootCertificate_usePSS(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_root_cert.test"

	// Test with use_pss = true
	configWithPSS := testPkiSecretBackendRootCertificateConfig_usePSS(path, true)
	checksWithPSS := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA with PSS"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldUsePSS, "true"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateSignatureAlgorithm(resourceName, "PSS"),
	}

	// Test with use_pss = false
	configWithoutPSS := testPkiSecretBackendRootCertificateConfig_usePSS(path, false)
	checksWithoutPSS := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA without PSS"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldUsePSS, "false"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateSignatureAlgorithm(resourceName, "PKCS1"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: configWithPSS,
				Check:  resource.ComposeTestCheckFunc(checksWithPSS...),
			},
			{
				Config: configWithoutPSS,
				Check:  resource.ComposeTestCheckFunc(checksWithoutPSS...),
			},
		},
	})
}

// TestPkiSecretBackendRootCertificate_keyUsage tests the key_usage field
func TestPkiSecretBackendRootCertificate_keyUsage(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_root_cert.test"

	config := testPkiSecretBackendRootCertificateConfig_keyUsage(path)
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA with Key Usage"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "3"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".0", "DigitalSignature"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".1", "CertSign"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".2", "CRLSign"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateKeyUsage(resourceName, []string{"DigitalSignature", "CertSign", "CRLSign"}),
	}

	testPkiSecretBackendRootCertificate(t, path, config, resourceName, checks, func(t *testing.T) {
		SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion1192)
	})
}

// TestPkiSecretBackendRootCertificate_usePSSAndKeyUsage tests both fields together
func TestPkiSecretBackendRootCertificate_usePSSAndKeyUsage(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_root_cert.test"

	config := testPkiSecretBackendRootCertificateConfig_usePSSAndKeyUsage(path)
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA with PSS and Key Usage"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "4096"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldUsePSS, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "3"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".0", "DigitalSignature"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".1", "CertSign"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".2", "CRLSign"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		assertCertificateSignatureAlgorithm(resourceName, "PSS"),
		assertCertificateKeyUsage(resourceName, []string{"DigitalSignature", "CertSign", "CRLSign"}),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

// TestPkiSecretBackendRootCertificate_usePSSWithECKey tests that use_pss is ignored for EC keys
func TestPkiSecretBackendRootCertificate_usePSSWithECKey(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_root_cert.test"

	config := testPkiSecretBackendRootCertificateConfig_usePSSWithECKey(path)
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA EC with PSS"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "ec"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "256"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldUsePSS, "true"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		// PSS should be ignored for EC keys, should use ECDSA
		assertCertificateSignatureAlgorithm(resourceName, "ECDSA"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

// TestPkiSecretBackendRootCertificate_keyUsageEmpty tests empty key_usage array
func TestPkiSecretBackendRootCertificate_keyUsageEmpty(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_root_cert.test"

	config := testPkiSecretBackendRootCertificateConfig_keyUsageEmpty(path)
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA with empty key usage"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "0"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),
		// Even with empty key_usage=[] in Terraform state, Vault still applies default key usages to the certificate
		// This validates that Vault's behavior is to always ensure root CAs have proper key usage
		assertCertificateKeyUsage(resourceName, []string{"CertSign", "CRLSign"}),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

// TestPkiSecretBackendRootCertificate_name_constraints is just like TestPkiSecretBackendRootCertificate_basic,
// but it uses the permitted_/excluded_ parameters for the name constraints extension.
func TestPkiSecretBackendRootCertificate_name_constraints(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())
	config := testPkiSecretBackendRootCertificateConfig_name_constraints(path)
	resourceName := "vault_pki_secret_backend_root_cert.test"
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, "internal"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCommonName, "test Root CA"),
		//resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "86400"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldFormat, "pem"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyFormat, "der"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "4096"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOu, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldCountry, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocality, "test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldProvince, "test"),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldSerialNumber),

		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedDNSDomains+".0", "example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedDNSDomains+".1", ".example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldExcludedDNSDomains+".0", "bad.example.com"),

		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedIPRanges+".0", "192.0.2.0/24"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedIPRanges+".1", "2001:db8::/32"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldExcludedIPRanges+".0", "192.0.3.0/24"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldExcludedIPRanges+".1", "2002::/16"),

		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedEmailAddresses+".0", "admin@example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedEmailAddresses+".1", "info@example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldExcludedEmailAddresses+".0", "root@example.com"),

		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedURIDomains+".0", "https://example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPermittedURIDomains+".1", "https://www.example.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldExcludedURIDomains+".0", "ftp://example.com"),
		func(s *terraform.State) error {
			return checkCertificateNameConstraints(resourceName, s)
		},
	}

	testPkiSecretBackendRootCertificate(t, path, config, resourceName, checks, func(t *testing.T) {
		SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
	})
}

func checkCertificateNameConstraints(resourceName string, s *terraform.State) error {
	var cert *x509.Certificate
	{
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		attrs := rs.Primary.Attributes

		// "pem" for resource_pki_secret_backend_root_cert root certs,
		// "pem_bundle" for resource_pki_secret_backend_root_sign_intermediate.
		if !(attrs["format"] == "pem" || attrs["format"] == "pem_bundle") {
			return errors.New("test only valid for resources configured with the 'pem' or 'pem_bundle' format")
		}

		certPEM := attrs["certificate"]
		if certPEM == "" {
			return fmt.Errorf("certificate from state cannot be empty")
		}

		b, _ := pem.Decode([]byte(certPEM))
		if err != nil {
			return err
		}

		cert, err = x509.ParseCertificate(b.Bytes)
		if err != nil {
			return err
		}
	}
	var failedChecks []error
	check := func(fieldName string, actual []string, expected ...string) {
		diff := deep.Equal(expected, actual)
		if len(diff) > 0 {
			failedChecks = append(failedChecks, fmt.Errorf("error in field %q: %v", fieldName, diff))
		}
	}

	check(consts.FieldPermittedDNSDomains, cert.PermittedDNSDomains, "example.com", ".example.com")
	check(consts.FieldExcludedDNSDomains, cert.ExcludedDNSDomains, "bad.example.com")
	var ips []string
	for _, ip := range cert.PermittedIPRanges {
		ips = append(ips, ip.String())
	}
	check(consts.FieldPermittedIPRanges, ips, "192.0.2.0/24", "2001:db8::/32")
	ips = nil
	for _, ip := range cert.ExcludedIPRanges {
		ips = append(ips, ip.String())
	}
	check(consts.FieldExcludedIPRanges, ips, "192.0.3.0/24", "2002::/16")
	check(consts.FieldPermittedEmailAddresses, cert.PermittedEmailAddresses, "admin@example.com", "info@example.com")
	check(consts.FieldExcludedEmailAddresses, cert.ExcludedEmailAddresses, "root@example.com")
	check(consts.FieldPermittedURIDomains, cert.PermittedURIDomains, "https://example.com", "https://www.example.com")
	check(consts.FieldExcludedURIDomains, cert.ExcludedURIDomains, "ftp://example.com")

	return errors.Join(failedChecks...)
}

func testPkiSecretBackendRootCertificate(t *testing.T, path string, config string, resourceName string, checks []resource.TestCheckFunc, preCheck func(t *testing.T)) {
	store := &testPKICertStore{}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			if preCheck != nil {
				preCheck(t)
			}
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: config,
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
				Config: config,
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
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

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
				Config: config,
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
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

func testPkiSecretBackendRootCertificateConfig_basic(path, extraConfig string) string {

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
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  signature_bits       = 512
  exclude_cn_from_sans = true
  ou                   = "test"
  organization         = "test"
  country              = "test"
  locality             = "test"
  province             = "test"
  max_path_length      = 0
  %s
}
`, path, extraConfig)

	return config
}

func testPkiSecretBackendRootCertificateConfig_name_constraints(path string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend					= vault_mount.test.path
  type						= "internal"
  common_name				= "test Root CA"
  ttl						= "86400"
  format					= "pem"
  private_key_format		= "der"
  key_type					= "rsa"
  key_bits					= 4096
  exclude_cn_from_sans		= true
  ou						= "test"
  organization				= "test"
  country					= "test"
  locality					= "test"
  province					= "test"
  permitted_dns_domains		= ["example.com",".example.com"]
  excluded_dns_domains		= ["bad.example.com"]
  permitted_ip_ranges		= ["192.0.2.0/24", "2001:db8::/32"]
  excluded_ip_ranges		= ["192.0.3.0/24", "2002::/16"]
  permitted_email_addresses = ["admin@example.com","info@example.com"]
  excluded_email_addresses	= ["root@example.com"]
  permitted_uri_domains		= ["https://example.com", "https://www.example.com"]
  excluded_uri_domains		= ["ftp://example.com"]
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

// Helper config functions for use_pss and key_usage tests

func testPkiSecretBackendRootCertificateConfig_usePSS(path string, usePSS bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test.path
  type               = "internal"
  common_name        = "test Root CA %s PSS"
  key_type           = "rsa"
  key_bits           = 2048
  use_pss            = %t
}
`, path, map[bool]string{true: "with", false: "without"}[usePSS], usePSS)
}

func testPkiSecretBackendRootCertificateConfig_keyUsage(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test.path
  type               = "internal"
  common_name        = "test Root CA with Key Usage"
  key_type           = "rsa"
  key_bits           = 2048
  key_usage          = ["DigitalSignature", "CertSign", "CRLSign"]
}
`, path)
}

func testPkiSecretBackendRootCertificateConfig_usePSSAndKeyUsage(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test.path
  type               = "internal"
  common_name        = "test Root CA with PSS and Key Usage"
  key_type           = "rsa"
  key_bits           = 4096
  use_pss            = true
  key_usage          = ["DigitalSignature", "CertSign", "CRLSign"]
}
`, path)
}

func testPkiSecretBackendRootCertificateConfig_usePSSWithECKey(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test.path
  type               = "internal"
  common_name        = "test Root CA EC with PSS"
  key_type           = "ec"
  key_bits           = 256
  use_pss            = true
}
`, path)
}

func testPkiSecretBackendRootCertificateConfig_keyUsageEmpty(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test.path
  type               = "internal"
  common_name        = "test Root CA with empty key usage"
  key_type           = "rsa"
  key_bits           = 2048
  key_usage          = []
}
`, path)
}

// Helper assertion functions for certificate validation

func assertCertificateSignatureAlgorithm(resourceName, expectedAlgo string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		certPEM := rs.Primary.Attributes[consts.FieldCertificate]
		if certPEM == "" {
			return fmt.Errorf("certificate is empty")
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("failed to decode PEM certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		var actualAlgo string
		switch cert.SignatureAlgorithm {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			actualAlgo = "PSS"
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			actualAlgo = "PKCS1"
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			actualAlgo = "ECDSA"
		default:
			actualAlgo = cert.SignatureAlgorithm.String()
		}

		if actualAlgo != expectedAlgo {
			return fmt.Errorf("expected signature algorithm %s, got %s (actual: %s)",
				expectedAlgo, actualAlgo, cert.SignatureAlgorithm.String())
		}

		return nil
	}
}

func assertCertificateKeyUsage(resourceName string, expectedUsages []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Skip the check for versions < 1.19.2
		if !provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion1192) {
			log.Printf("[INFO] Skipping key_usage assertion for Vault version < 1.19.2 (key_usage parameter support was fixed in 1.19.2)")
			return nil
		}

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		certPEM := rs.Primary.Attributes[consts.FieldCertificate]
		if certPEM == "" {
			return fmt.Errorf("certificate is empty")
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("failed to decode PEM certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		// Map x509.KeyUsage bits to string names
		actualUsages := []string{}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			actualUsages = append(actualUsages, "DigitalSignature")
		}
		if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
			actualUsages = append(actualUsages, "ContentCommitment")
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			actualUsages = append(actualUsages, "KeyEncipherment")
		}
		if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
			actualUsages = append(actualUsages, "DataEncipherment")
		}
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			actualUsages = append(actualUsages, "KeyAgreement")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			actualUsages = append(actualUsages, "CertSign")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
			actualUsages = append(actualUsages, "CRLSign")
		}
		if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
			actualUsages = append(actualUsages, "EncipherOnly")
		}
		if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
			actualUsages = append(actualUsages, "DecipherOnly")
		}

		// Check if all expected usages are present
		for _, expected := range expectedUsages {
			found := false
			for _, actual := range actualUsages {
				if actual == expected {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("expected key usage %s not found in certificate. Actual usages: %v",
					expected, actualUsages)
			}
		}

		return nil
	}
}
