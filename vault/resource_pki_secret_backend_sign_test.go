// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendSign_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_sign.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendSignConfig_basic(rootPath, intermediatePath, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", intermediatePath),
					resource.TestCheckResourceAttr(resourceName, "common_name", "cert.test.my.domain"),
					testValidateCSR(resourceName),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion111), nil
				},
				Config: testPkiSecretBackendSignConfig_basic(rootPath, intermediatePath, `issuer_ref = "test"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerRef, "test"),
				),
			},
		},
	})
}

func testPkiSecretBackendSignConfig_basic(rootPath, intermediatePath, extraConfig string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = "pki"
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test-root.path
  type               = "internal"
  common_name        = "my.domain"
  ttl                = "86400"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  ou                 = "test"
  organization       = "test"
  country            = "test"
  locality           = "test"
  province           = "test"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test-intermediate.path
  type        = vault_pki_secret_backend_root_cert.test.type
  common_name = "test.my.domain"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend               = vault_mount.test-root.path
  csr                   = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name           = "test.my.domain"
  permitted_dns_domains = [".test.my.domain"]
  ou                    = "test"
  organization          = "test"
  country               = "test"
  locality              = "test"
  province              = "test"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  backend     = vault_mount.test-intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.test.certificate
}

resource "vault_pki_secret_backend_role" "test" {
  backend          = vault_pki_secret_backend_intermediate_set_signed.test.backend
  name             = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  max_ttl          = "3600"
  key_usage        = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_sign" "test" {
  backend     = vault_pki_secret_backend_role.test.backend
  name        = vault_pki_secret_backend_role.test.name
  csr         = <<EOT
-----BEGIN CERTIFICATE REQUEST-----
MIIEqDCCApACAQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTY2Vy
dC50ZXN0Lm15LmRvbWFpbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJupYCQ8UVCWII1Zof1c6YcSSaM9hEaDU78cfKP5RoSeH10BvrWRfT+mzCONVpNP
CW9Iabtvk6hm0ot6ilnndEyVJbc0g7hdDLBX5BM25D+DGZGJRKUz1V+uBrWmXtIt
Vonj7JTDTe7ViH0GDsB7CvqXFGXO2a2cDYBchLkL6vQiFPshxvUsLtwxuy/qdYgy
X6ya+AUoZcoQGy1XxNjfH6cPtWSWQGEp1oPR6vL9hU3laTZb3C+VV4jZem+he8/0
V+qV6fLG92WTXm2hmf8nrtUqqJ+C7mW/RJod+TviviBadIX0OHXW7k5HVsZood01
te8vMRUNJNiZfa9EMIK5oncbQn0LcM3Wo9VrjpL7jREb/4HCS2gswYGv7hzk9cCS
kVY4rDucchKbApuI3kfzmO7GFOF5eiSkYZpY/czNn7VVM3WCu6dpOX4+3rhgrZQw
kY14L930DaLVRUgve/zKVP2D2GHdEOs+MbV7s96UgigT9pXly/yHPj+1sSYqmnaD
5b7jSeJusmzO/nrwXVGLsnezR87VzHl9Ux9g5s6zh+R+PrZuVxYsLvoUpaasH47O
gIcBzSb/6pSGZKAUizmYsHsR1k88dAvsQ+FsUDaNokdi9VndEB4QPmiFmjyLV+0I
1TFoXop4sW11NPz1YCq+IxnYrEaIN3PyhY0GvBJDFY1/AgMBAAGgADANBgkqhkiG
9w0BAQsFAAOCAgEActuqnqS8Y9UF7e08w7tR3FPzGecWreuvxILrlFEZJxiLPFqL
It7uJvtypCVQvz6UQzKdBYO7tMpRaWViB8DrWzXNZjLMrg+QHcpveg8C0Ett4scG
fnvLk6fTDFYrnGvwHTqiHos5i0y3bFLyS1BGwSpdLAykGtvC+VM8mRyw/Y7CPcKN
77kebY/9xduW1g2uxWLr0x90RuQDv9psPojT+59tRLGSp5Kt0IeD3QtnAZEFE4aN
vt+Pd69eg3BgZ8ZeDgoqAw3yppvOkpAFiE5pw2qPZaM4SRphl4d2Lek2zNIMyZqv
do5zh356HOgXtDaSg0POnRGrN/Ua+LMCRTg6GEPUnx9uQb/zt8Zu0hIexDGyykp1
OGqtWlv/Nc8UYuS38v0BeB6bMPeoqQUjkqs8nHlAEFn0KlgYdtDC+7SdQx6wS4te
dBKRNDfC4lS3jYJgs55jHqonZgkpSi3bamlxpfpW0ukGBcmq91wRe4bOw/4uD/vf
UwqMWOdCYcU3mdYNjTWy22ORW3SGFQxMBwpUEURCSoeqWr6aJeQ7KAYkx1PrB5T8
OTEc13lWf+B0PU9UJuGTsmpIuImPDVd0EVDayr3mT5dDbqTVDbe8ppf2IswABmf0
o3DybUeUmknYjl109rdSf+76nuREICHatxXgN3xCMFuBaN4WLO+ksd6Y1Ys=
-----END CERTIFICATE REQUEST-----
EOT
  common_name = "cert.test.my.domain"
  %s
}
`, rootPath, intermediatePath, extraConfig)
}

func TestPkiSecretBackendSign_renew(t *testing.T) {
	path := "pki-root-" + strconv.Itoa(acctest.RandInt())

	var store testPKICertStore

	resourceName := "vault_pki_secret_backend_sign.test"
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", path),
		resource.TestCheckResourceAttr(resourceName, "common_name", "cert.test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "1h"),
		resource.TestCheckResourceAttr(resourceName, "min_seconds_remaining", "3595"),
		resource.TestCheckResourceAttrSet(resourceName, "expiration"),
		resource.TestCheckResourceAttrSet(resourceName, "serial"),
		resource.TestCheckResourceAttrSet(resourceName, "renew_pending"),
		testValidateCSR(resourceName),
	}
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendSignConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testCapturePKICert(resourceName, &store),
					)...,
				),
			},
			{
				// test renewal based on cert expiry
				PreConfig: testWaitCertExpiry(&store),
				Config:    testPkiSecretBackendSignConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, &store),
						testCapturePKICert(resourceName, &store),
					)...,
				),
			},
			{
				// test unmounted backend
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					if err := client.Sys().Unmount(path); err != nil {
						t.Fatal(err)
					}
				},
				Config: testPkiSecretBackendSignConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, &store),
					)...,
				),
			},
		},
	})
}

func testPkiSecretBackendSignConfig_renew(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test-root.path
  type               = "internal"
  common_name        = "my.domain"
  ttl                = "86400"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  ou                 = "test"
  organization       = "test"
  country            = "test"
  locality           = "test"
  province           = "test"
}

resource "vault_pki_secret_backend_role" "test" {
  backend          = vault_pki_secret_backend_root_cert.test.backend
  name             = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  max_ttl          = "3600"
  key_usage        = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_sign" "test" {
  backend               = vault_mount.test-root.path
  name                  = vault_pki_secret_backend_role.test.name
  csr                   = <<EOT
-----BEGIN CERTIFICATE REQUEST-----
MIIEqDCCApACAQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTY2Vy
dC50ZXN0Lm15LmRvbWFpbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJupYCQ8UVCWII1Zof1c6YcSSaM9hEaDU78cfKP5RoSeH10BvrWRfT+mzCONVpNP
CW9Iabtvk6hm0ot6ilnndEyVJbc0g7hdDLBX5BM25D+DGZGJRKUz1V+uBrWmXtIt
Vonj7JTDTe7ViH0GDsB7CvqXFGXO2a2cDYBchLkL6vQiFPshxvUsLtwxuy/qdYgy
X6ya+AUoZcoQGy1XxNjfH6cPtWSWQGEp1oPR6vL9hU3laTZb3C+VV4jZem+he8/0
V+qV6fLG92WTXm2hmf8nrtUqqJ+C7mW/RJod+TviviBadIX0OHXW7k5HVsZood01
te8vMRUNJNiZfa9EMIK5oncbQn0LcM3Wo9VrjpL7jREb/4HCS2gswYGv7hzk9cCS
kVY4rDucchKbApuI3kfzmO7GFOF5eiSkYZpY/czNn7VVM3WCu6dpOX4+3rhgrZQw
kY14L930DaLVRUgve/zKVP2D2GHdEOs+MbV7s96UgigT9pXly/yHPj+1sSYqmnaD
5b7jSeJusmzO/nrwXVGLsnezR87VzHl9Ux9g5s6zh+R+PrZuVxYsLvoUpaasH47O
gIcBzSb/6pSGZKAUizmYsHsR1k88dAvsQ+FsUDaNokdi9VndEB4QPmiFmjyLV+0I
1TFoXop4sW11NPz1YCq+IxnYrEaIN3PyhY0GvBJDFY1/AgMBAAGgADANBgkqhkiG
9w0BAQsFAAOCAgEActuqnqS8Y9UF7e08w7tR3FPzGecWreuvxILrlFEZJxiLPFqL
It7uJvtypCVQvz6UQzKdBYO7tMpRaWViB8DrWzXNZjLMrg+QHcpveg8C0Ett4scG
fnvLk6fTDFYrnGvwHTqiHos5i0y3bFLyS1BGwSpdLAykGtvC+VM8mRyw/Y7CPcKN
77kebY/9xduW1g2uxWLr0x90RuQDv9psPojT+59tRLGSp5Kt0IeD3QtnAZEFE4aN
vt+Pd69eg3BgZ8ZeDgoqAw3yppvOkpAFiE5pw2qPZaM4SRphl4d2Lek2zNIMyZqv
do5zh356HOgXtDaSg0POnRGrN/Ua+LMCRTg6GEPUnx9uQb/zt8Zu0hIexDGyykp1
OGqtWlv/Nc8UYuS38v0BeB6bMPeoqQUjkqs8nHlAEFn0KlgYdtDC+7SdQx6wS4te
dBKRNDfC4lS3jYJgs55jHqonZgkpSi3bamlxpfpW0ukGBcmq91wRe4bOw/4uD/vf
UwqMWOdCYcU3mdYNjTWy22ORW3SGFQxMBwpUEURCSoeqWr6aJeQ7KAYkx1PrB5T8
OTEc13lWf+B0PU9UJuGTsmpIuImPDVd0EVDayr3mT5dDbqTVDbe8ppf2IswABmf0
o3DybUeUmknYjl109rdSf+76nuREICHatxXgN3xCMFuBaN4WLO+ksd6Y1Ys=
-----END CERTIFICATE REQUEST-----
EOT
  common_name           = "cert.test.my.domain"
  ttl                   = "1h"
  auto_renew            = true
  min_seconds_remaining = "3595"
}
`, rootPath)
}

func testValidateCSR(resourceName string) resource.TestCheckFunc {
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

		certPEM := attrs["certificate"]
		if certPEM == "" {
			return fmt.Errorf("certificate from state cannot be empty")
		}

		b, _ := pem.Decode([]byte(certPEM))
		if err != nil {
			return err
		}

		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return err
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

		if !reflect.DeepEqual(csr.PublicKey, cert.PublicKey) {
			return fmt.Errorf("certificate is invalid, public key mismatch, csr=%v, cert=%v",
				csr.PublicKey, cert.PublicKeyAlgorithm)
		}

		return nil
	}
}
