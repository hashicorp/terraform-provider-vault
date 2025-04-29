// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var signConfigBlock = `resource "vault_pki_secret_backend_sign" "test" {
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
		cert_metadata         = "dGVzdCBtZXRhZGF0YQ=="
	}
`

var certConfigBlock = `resource "vault_pki_secret_backend_cert" "test" {
  backend               = vault_pki_secret_backend_role.test.backend
  name                  = vault_pki_secret_backend_role.test.name
  common_name           = "cert.test.my.domain"
  ttl                   = "720h"
  min_seconds_remaining = 60
  cert_metadata         = "dGVzdCBtZXRhZGF0YQ=="
}
`

func TestAccDataSourcePKISecretCertMetadata(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")

	dataName := "data.vault_pki_secret_backend_cert_metadata.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretCertMetadataConfig(backend, signConfigBlock, "vault_pki_secret_backend_sign"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldCertMetadata, "dGVzdCBtZXRhZGF0YQ=="),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldExpiration),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldRole),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldSerialNumber),
				),
			},
			{
				Config: testPKISecretCertMetadataConfig(backend, certConfigBlock, "vault_pki_secret_backend_cert"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldCertMetadata, "dGVzdCBtZXRhZGF0YQ=="),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldExpiration),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldRole),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldSerialNumber),
				),
			},
		},
	})
}

func testPKISecretCertMetadataConfig(backend, block, resourceName string) string {
	return fmt.Sprintf(`resource "vault_mount" "test-root" {
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
		backend           = vault_pki_secret_backend_root_cert.test.backend
		name              = "test"
		allowed_domains   = ["test.my.domain"]
		allow_subdomains  = true
		max_ttl           = "3600"
		key_usage         = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
		no_store_metadata = false
	}

	%s

	data "vault_pki_secret_backend_cert_metadata" "test" {
		path = vault_mount.test-root.path
		serial = %s.test.serial_number
	}
`, backend, block, resourceName)
}
