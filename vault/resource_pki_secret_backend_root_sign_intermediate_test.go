// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-version"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	testPKICARoot = `-----BEGIN CERTIFICATE-----
MIIF6TCCA9GgAwIBAgIUG/fx8oIjdqu0uSCc+x/3AkpOZPgwDQYJKoZIhvcNAQEL
BQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJh
bmNpc2NvMRAwDgYDVQQKEwdSb290T3JnMRwwGgYDVQQLExNPcmdhbml6YXRpb25h
bCBVbml0MRgwFgYDVQQDEw9Sb290T3JnIFJvb3QgQ0EwHhcNMjIwNDIyMjIxODAw
WhcNMjIwNDIzMjIxODI4WjB8MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAU
BgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB1Jvb3RPcmcxHDAaBgNVBAsT
E09yZ2FuaXphdGlvbmFsIFVuaXQxGDAWBgNVBAMTD1Jvb3RPcmcgUm9vdCBDQTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZeQyyKDUnWRnyi+8rfpvx/
0Cz/4LVp0B52m3ilxc0vIz3hdWTJsYE9vqwsNgPsYGJaFKUuXZCedZAug9I5X6rf
PDusNaamn+cAOzMySo5xwWrXaW0U3aBkm3vQprnVGHnsqOzCJGG4Ez/v7b8qknsw
yCE5C5S7qMNkZZgNHRYbC/oBwz11+I3bCIWw7DIsL0T/unuyux+gGWmIwd5hypBY
YmeGcgXcNPmZBtNX9s6c3J63P7V1PZmdhg6saG0/bUiiG1niYx8xwQWkgE0B2S39
X5tuZdEI1VvRHPAcQAtZoq0bU0zi8RKp6Z09iCwuoWwZ5wuzfP70XdWqYmZbNPI2
OWIUVd4Aa4cNE+4FrRrmSIqYEbmtlBx3YFD3ZGIxD21zfLydJTqNswWd6m2v05ur
M+0PUaXor/CG/6sTFtpsa5i+wMcjhpLCOOx1XX6rlQkErwR8+xY+7aojAwkreQYn
t4/iI4vfkeKlreSTbN+EzwlYUhZF40GnPuVTGH7rf4/8z0uWmUh8ulhqLEKjUeLd
NA/t5yYo8sTpv3A+ngYZlOakVIOwNmweLgTFPFYiG4TeguU+Kb0aFvKLcJ105v8g
boExnsUApJ9Er+LSNuVl6uldYA2u8067ekWYEuVI8CVsk3wb5Eawu2SDGt2ZDtcp
6TB09QH0AzQzSVlPvAlhAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBRSG+J2QK+KoNunXfW3cER9QuwpjzAfBgNVHSME
GDAWgBRSG+J2QK+KoNunXfW3cER9QuwpjzANBgkqhkiG9w0BAQsFAAOCAgEALeLv
pVvBtIB4IVdQ6cfJQYZbPpkeszRDrlOlgDMWuD8CzHssbnUjclfDdRjdLIQbif+e
5u2/yeRRCBTYjwf1yGCyrWcs9vsHkjqeafyq0grS3zoPBf0JCAH/bI6NO1CUM39I
qyRTotdwLBemKmGd3ZUHCUpq9FQgPT/Yy6XIxfkAfGi/FbudxHOQGFJDXxDMPmV1
55HSBILwSEf1Z/aSW8+yzgtEzipPZIDGoLyYw8Ggew2Z535NdPSSF96f8F4QsXVs
mJJiidga36+z+7e99tEcw+V4GkGuSHG0SGJFqh8apDwNOOPfGBQmp3xkNhuM8xKi
u/gCAcoj1aDuFQzflq3zo2cSAPBoUFyma0iL22fHGvLX8Es+C3uYKucuaToBxN8t
j/IHV06aH+nXuAvNtvneL6TW3zsbYXA+GF//9PigFXutC/Fa3l00RNkIfApXsl5H
Xk+u708W1+h+hy+KWvZGyXmylRoHsMC2kCwi3/wzgS6xloHuNoai6OGE9EbZKV3D
Efyw5RK4c4betgp1tlKnWrr68xFoxJaX8F79bHGwMhuhA3qMfqZZgGmJu6W4qurd
TBI3smImFBUe0JQP7Gjkv77xBO3+WBIiL/o8tAxzMG83WwIkxgZiHd41RMEaYq03
90biK9JhpmCai5cVk0B8dPL+NS0nJC1XYzZMg/0=
-----END CERTIFICATE-----`

	testPKICAInter1 = `-----BEGIN CERTIFICATE-----
MIIE5TCCAs2gAwIBAgIUBchlYVQE28rilenVgghsNINDOmswDQYJKoZIhvcNAQEL
BQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJh
bmNpc2NvMRAwDgYDVQQKEwdSb290T3JnMRwwGgYDVQQLExNPcmdhbml6YXRpb25h
bCBVbml0MRgwFgYDVQQDEw9Sb290T3JnIFJvb3QgQ0EwHhcNMjIwNDIyMjIxODAw
WhcNMjIwNzMxMjIxODMwWjB4MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAU
BgNVBAcTDVNhbiBGcmFuY2lzY28xDzANBgNVBAoTBlN1Yk9yZzEQMA4GA1UECxMH
U3ViVW5pdDEhMB8GA1UEAxMYU3ViT3JnIEludGVybWVkaWF0ZSAxIENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2AUomcioJ0dxl8sNI9quhf67nE6d
OisoYQFTIsPCrCMHUc0usJK89sz6vl2YcjZNB+9UDwl4YDolZuwSm/haPOl/DPKs
Q2k+ULAyQm5Lgo5VeY9F995KanK3LpOsvNhhPrtOd8WpAzDYyRCh9lpEVm5bRNRP
BLO4vXXIpnV6vF/Tl62SBkUSg1omfxo4wKVxbr9qsKV38s72YDYRyoO7kvpDLANr
dTONBFb1+bbCsTXza4sdf1hT0kVOqQ2cuXkx2F1ZYoxFy+PiD3o88zPSemAMKDLx
WXysTviEWPROzGjhjp/IklAg9QUK/xFV5eOoY1u/U1S3nENa/WH9DTxczwIDAQAB
o2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
gOExNQVzrey7daGBbYstrRvnjHgwHwYDVR0jBBgwFoAUUhvidkCviqDbp131t3BE
fULsKY8wDQYJKoZIhvcNAQELBQADggIBALF+Op35RzkV4MVog4G0SZXewS2PRl8R
55DPy+HHU8NM2xJCce1Hy3fcUP06KbYb9vUT2AEwCNLhg0X9iMbPqLLDWRSN2DyI
RIpVF73sFpg5zndpOVNe22manJM6rYp6deA/p6g0Oq0qM9flRZzUv7F1KZpz3Nqp
TQ4I8YeIRXkcqIBaZ0m9QLpKIoz3nT23M4Dexu/ZiB0wb2cpzyV9puEAE8vuAqvX
hCLRfXypMWwnotb2qRW8avNiEutzNTGaUP5kACUjZrPfvIEtFgHUwJo+PI1E3XC0
zUauudQjqju7JrIiCGfdKCCaIeiayNLppDLXhDfHJphyfbH/r4orz5zVXpBZSnvc
O0Ch4gv9PnJGGJiWrvKUhJ/XbConPKGqGVaC30rQPxG7UYTDDXjOppzJXZTvXuC/
DCwVCYbWURB4+S2n86fXCyyQQp+vmbAZ3skpATmS9WugUYgTjJKVPiOpvHSAIpID
u8rSVwdurDjlMknnWYi9v8kUoF00yLHGlE7Qwbmy4dIQVf5ODvCSl338hXKz4UR8
GkeB+wXrYZuQVAiMYwLnL8IWWaezpdzb/9US3SuSlNWmJodv503OzXbR3ZLJSpmG
RywQn6l10JjFHgu19AF0d8FxePSNjF7EBxMTnVRNnDUlMaQ4mBBmbuLpFSdC0tT+
8J7F3SAJemsj
-----END CERTIFICATE-----`

	testPKICAInter2 = `-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIUd+Kg3J4m1JQV4jfQqTDpoBflzkswDQYJKoZIhvcNAQEL
BQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJh
bmNpc2NvMQ8wDQYDVQQKEwZTdWJPcmcxEDAOBgNVBAsTB1N1YlVuaXQxITAfBgNV
BAMTGFN1Yk9yZyBJbnRlcm1lZGlhdGUgMSBDQTAeFw0yMjA0MjIyMjE4MDFaFw0y
MjA0MjMyMjE4MzFaMHgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNU2FuIEZyYW5jaXNjbzEPMA0GA1UEChMGU3ViT3JnMRAwDgYDVQQLEwdTdWJV
bml0MSEwHwYDVQQDExhTdWJPcmcgSW50ZXJtZWRpYXRlIDIgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJS0eOipFCJyCBhICPiz/AReEpN+xCzaU3
qS48S6wneRi4XOmIRmwCIBidif0KiKA/FNnW1Zn46KLAmUFLJ62R8xkybcMTnXyS
5BP2RjSeuzsiroikc8G+47jsbaPHQ31LZsbnXT/qhyn4z4ZrinogZ2oTylWbej4d
hbaDSM6s09I+/8hO1e3ozO7bbeSuGh96ZJxybqhn2OqGM2n9TpOFl0/tNLgLmWAK
wTQPA1o6y9aEwo3rhcrr+RYVRSkZcYTCV8IWl+0Fc5wPmU76zRQjBjQAnyTtM5FQ
w37Gqxfqcfco9ft164o/UGpNfH9a5lTgGEYLfbLyXeCoB2H+BNjrAgMBAAGjYzBh
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqcjXs
II8inLX35oP8L5gVI3UvwDAfBgNVHSMEGDAWgBSA4TE1BXOt7Lt1oYFtiy2tG+eM
eDANBgkqhkiG9w0BAQsFAAOCAQEAW53sApGzlLklvsbFjtu97efGcK2GgSVgnleg
AYw6VtVP/O+DlxoJozsPBIAxtAW9VHow4zMl7IYFtGVOIQXJaG2h93KajeKq58Sv
BZhUKotj0sFUXe59xdoNeejNppULyC57QtgjZvswiY12gVqHPf6kil7laDBPHmoy
8ZLK1vTceoSP+/2NlXibG4h1RkTYTWmPHLJRC7BAJ8Nki9wDY4GQDytzPOMBEqa1
KOKcpw4F09qh705aVZnJj0kZwIJugIhq9K2Q+auUnwaUkVtpyF8vlkDBSQMJPhln
DjZxoKDOAPYwWRsTAgup5jWWwVoCG/GA8cWMDwO1Ul5UYWHalg==
-----END CERTIFICATE-----`
)

func TestPkiSecretBackendRootSignIntermediate_basic_default(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"
	commonName := "SubOrg Intermediate CA"

	skip := func(minVersion *version.Version) func() (bool, error) {
		return func() (bool, error) {
			meta := testProvider.Meta().(*provider.ProviderMeta)
			return !meta.IsAPISupported(minVersion), nil
		}
	}
	resourceName := "vault_pki_secret_backend_root_sign_intermediate.test"
	checks := testCheckPKISecretRootSignIntermediate(resourceName, rootPath, commonName, format, "", x509.SHA256WithRSA, false)
	store := &testPKICertStore{}
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false),
				Check: resource.ComposeTestCheckFunc(
					checks,
					testCapturePKICert(resourceName, store),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion111), nil
				},
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false, `issuer_ref = "test"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerRef, "test"),
				),
			},
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, true),
				Check: resource.ComposeTestCheckFunc(
					checks,
					testPKICertRevocation(rootPath, store),
				),
			},
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false,
					`not_before_duration = "120s"`),
				Check: resource.ComposeTestCheckFunc(
					checks,
					resource.TestCheckResourceAttr(resourceName, consts.FieldNotBeforeDuration, "120s"),
					testPKICert(resourceName, func(cert *x509.Certificate) error {
						approximaetNotBeforeDuration := time.Now().Sub(cert.NotBefore).Seconds()
						if approximaetNotBeforeDuration < 110 || approximaetNotBeforeDuration > 130 {
							// Note that we use a tolerance of 10 seconds, which should be plenty
							return fmt.Errorf("notBefore duration expected to be ~ 120s, but was %#v", approximaetNotBeforeDuration)
						}
						return nil
					}),
				),
			},
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false,
					`skid = "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6"`),
				Check: resource.ComposeTestCheckFunc(
					checks,
					resource.TestCheckResourceAttr(resourceName, consts.FieldSKID, "14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6"),
					testPKICert(resourceName, func(cert *x509.Certificate) error {
						expected := []byte{0x14, 0x2E, 0xB3, 0x17, 0xB7, 0x58, 0x56, 0xCB, 0xAE, 0x50, 0x09, 0x40, 0xE6, 0x1F, 0xAF, 0x9D, 0x8B, 0x14, 0xC2, 0xC6}
						if !bytes.Equal(expected, cert.SubjectKeyId) {
							return fmt.Errorf("SubjectKeyID expected %#v but got %#v", expected, cert.SubjectKeyId)
						}
						return nil
					}),
				),
			},
			{
				SkipFunc: skip(provider.VaultVersion112),
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false,
					`use_pss = true`),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate(resourceName, rootPath, commonName, format, "", x509.SHA256WithRSAPSS, false),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsePSS, "true"),
				),
			},
			{
				SkipFunc: skip(provider.VaultVersion118),
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false,
					`key_usage = ["CertSign", "DigitalSignature"]`),
				Check: resource.ComposeTestCheckFunc(
					checks,
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".0", "CertSign"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyUsage+".1", "DigitalSignature"),
					testPKICert(resourceName, func(cert *x509.Certificate) error {
						if 0 == cert.KeyUsage&x509.KeyUsageCertSign {
							return fmt.Errorf("KeyUsage expected %b, got %b",
								x509.KeyUsageKeyAgreement|x509.KeyUsageCertSign,
								cert.KeyUsage)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false, `format = "pem"`),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, "pem", "", x509.SHA256WithRSA, false),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_der(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false, `format = "der"`),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, "der", "", x509.SHA256WithRSA, false),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem_bundle(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false, `format = "pem_bundle"`),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, "pem_bundle", "", x509.SHA256WithRSA, false),
			},
		},
	})
}

func notAfter(t time.Time) string {
	return fmt.Sprintf("not_after = %q", t.Format(time.RFC3339))
}

func TestPkiSecretBackendRootSignIntermediate_not_after(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	commonName := "SubOrg Intermediate CA"
	notAfterTime := time.Now().Add(5 * time.Hour)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, false, `format = "der"`, notAfter(notAfterTime)),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, "der", notAfterTime.Format(time.RFC3339), x509.SHA256WithRSA, false),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_name_constraints_pem_bundle(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem_bundle"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_name_constraints(rootPath, intermediatePath, format, false, ""),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA256WithRSA, true),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_signature_bits(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem_bundle"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_signature_bits(rootPath, intermediatePath, format, "384"),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA384WithRSA, false),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", consts.FieldSignatureBits, "384"),
				),
			},
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_signature_bits(rootPath, intermediatePath, format, "512"),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA512WithRSA, false),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", consts.FieldSignatureBits, "512"),
				),
			},
		},
	})
}
func TestPkiSecretBackendRootSignIntermediate_key_usage(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			// Skip if Vault version is less than 1.19.2 (when key_usage validation was improved)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion1192)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				// Test with valid key_usage values
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(
					rootPath,
					intermediatePath,
					false,
					`key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]`,
				),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA256WithRSA, false),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.#", "3"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.0", "DigitalSignature"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.1", "KeyAgreement"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.2", "KeyEncipherment"),
					// Verify actual certificate key usage
					testPKICert("vault_pki_secret_backend_root_sign_intermediate.test", func(cert *x509.Certificate) error {
						expectedUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
						if 0 == cert.KeyUsage&expectedUsage {
							return fmt.Errorf("Certificate KeyUsage expected to include %b, got %b", expectedUsage, cert.KeyUsage)
						}
						return nil
					}),
				),
			},
			{
				// Test without key_usage (not passed) - should use defaults
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(
					rootPath,
					intermediatePath,
					false,
				),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA256WithRSA, false),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.#", "0"),
					// Verify certificate gets default CA key usages
					testPKICert("vault_pki_secret_backend_root_sign_intermediate.test", func(cert *x509.Certificate) error {
						// Default key usages for CA certificates include CertSign and CRLSign
						if 0 == cert.KeyUsage&x509.KeyUsageCertSign {
							return fmt.Errorf("Default certificate KeyUsage should include CertSign, got %b", cert.KeyUsage)
						}
						if 0 == cert.KeyUsage&x509.KeyUsageCRLSign {
							return fmt.Errorf("Default certificate KeyUsage should include CRLSign, got %b", cert.KeyUsage)
						}
						return nil
					}),
				),
			},
			{
				// Test with explicitly empty key_usage array - Vault should still apply defaults
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(
					rootPath,
					intermediatePath,
					false,
					`key_usage = []`,
				),
				Check: resource.ComposeTestCheckFunc(
					testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format, "", x509.SHA256WithRSA, false),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "key_usage.#", "0"),
					// Verify certificate gets default CA key usages even with empty array
					testPKICert("vault_pki_secret_backend_root_sign_intermediate.test", func(cert *x509.Certificate) error {
						// Default key usages for CA certificates include CertSign and CRLSign
						if 0 == cert.KeyUsage&x509.KeyUsageCertSign {
							return fmt.Errorf("Default certificate KeyUsage should include CertSign, got %b", cert.KeyUsage)
						}
						if 0 == cert.KeyUsage&x509.KeyUsageCRLSign {
							return fmt.Errorf("Default certificate KeyUsage should include CRLSign, got %b", cert.KeyUsage)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem_bundle_multiple_intermediates(t *testing.T) {
	t.Skip("Skip until VAULT-6700 is resolved")

	random := strconv.Itoa(acctest.RandInt())
	rootPath := "pki-root-" + random
	intermediate1Path := "pki-intermediate1-" + random
	intermediate2Path := "pki-intermediate2-" + random
	format := "pem_bundle"
	commonName := "SubOrg Intermediate 2 CA"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_multiple_inter(rootPath, intermediate1Path, intermediate2Path, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.two", intermediate1Path, commonName, format, "", x509.SHA256WithRSA, false),
			},
		},
	})
}

func testCheckPKISecretRootSignIntermediate(res, path, commonName, format string, notAfter string, expectedSignatureAlgorithm x509.SignatureAlgorithm, checkNameConstraintsAttrs bool) resource.TestCheckFunc {
	checks := []resource.TestCheckFunc{resource.TestCheckResourceAttr(res, "backend", path),
		resource.TestCheckResourceAttr(res, "common_name", commonName),
		resource.TestCheckResourceAttr(res, "ou", "SubUnit"),
		resource.TestCheckResourceAttr(res, "organization", "SubOrg"),
		resource.TestCheckResourceAttr(res, "country", "US"),
		resource.TestCheckResourceAttr(res, "locality", "San Francisco"),
		resource.TestCheckResourceAttr(res, "province", "CA"),
		resource.TestCheckResourceAttr(res, "format", format),
		resource.TestCheckResourceAttrSet(res, "serial_number"),
		assertPKICertificateBundle(res, format),
		assertPKICAChain(res),
		assertCertificateAttributes(res, notAfter, expectedSignatureAlgorithm),
	}
	if checkNameConstraintsAttrs {
		// Note that the name constraints extension field values are the same as in resource_pki_secret_backend_root_cert_test.go
		// only for dev convinience (i.e. laziness).
		checks = append(checks,
			resource.TestCheckResourceAttr(res, consts.FieldPermittedDNSDomains+".0", "example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldPermittedDNSDomains+".1", ".example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldExcludedDNSDomains+".0", "bad.example.com"),

			resource.TestCheckResourceAttr(res, consts.FieldPermittedIPRanges+".0", "192.0.2.0/24"),
			resource.TestCheckResourceAttr(res, consts.FieldPermittedIPRanges+".1", "2001:db8::/32"),
			resource.TestCheckResourceAttr(res, consts.FieldExcludedEmailAddresses+".0", "root@example.com"),

			resource.TestCheckResourceAttr(res, consts.FieldPermittedEmailAddresses+".0", "admin@example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldPermittedEmailAddresses+".1", "info@example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldExcludedEmailAddresses+".0", "root@example.com"),

			resource.TestCheckResourceAttr(res, consts.FieldPermittedURIDomains+".0", "https://example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldPermittedURIDomains+".1", "https://www.example.com"),
			resource.TestCheckResourceAttr(res, consts.FieldExcludedURIDomains+".0", "ftp://example.com"),
			func(s *terraform.State) error {
				return checkCertificateNameConstraints(res, s)
			},
		)
	}
	return resource.ComposeTestCheckFunc(checks...)
}

func assertPKICertificateBundle(res, expectedFormat string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[res]
		if !ok {
			return fmt.Errorf("resource %q not found in the state", res)
		}

		actualFormat := rs.Primary.Attributes["format"]
		if expectedFormat != actualFormat {
			return fmt.Errorf("expected format %q, actual %q", expectedFormat, actualFormat)
		}

		var expected string
		switch expectedFormat {
		case "pem", "pem_bundle":
			m := map[string]interface{}{
				"certificate": rs.Primary.Attributes["certificate"],
				"issuing_ca":  rs.Primary.Attributes["issuing_ca"],
			}
			chain, err := parseCertChain(m, false, false)
			if err != nil {
				return err
			}
			expected = strings.Join(chain, "\n")
		}

		actual := rs.Primary.Attributes["certificate_bundle"]
		if expected != actual {
			return fmt.Errorf("expected certificate_bundle %q, actual %q", expected, actual)
		}

		return nil
	}
}

func assertPKICAChain(res string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[res]
		if !ok {
			return fmt.Errorf("resource %q not found in the state", res)
		}

		if err := resource.TestCheckResourceAttr(res, "ca_chain.#", "2")(s); err != nil {
			return err
		}

		expected := []string{
			rs.Primary.Attributes["issuing_ca"],
			rs.Primary.Attributes["certificate"],
		}
		actual := []string{
			rs.Primary.Attributes["ch_chain.0"],
			rs.Primary.Attributes["ch_chain.1"],
		}

		if reflect.DeepEqual(expected, actual) {
			return fmt.Errorf("expected ca_chain %q, actual %q", expected, actual)
		}

		return nil
	}
}

func assertCertificateAttributes(res string, notAfter string, expectedSignatureAlgorithm x509.SignatureAlgorithm) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[res]
		if !ok {
			return fmt.Errorf("resource %q not found in the state", res)
		}
		format := rs.Primary.Attributes["format"]
		var rawCert []byte
		switch format {
		case "pem", "pem_bundle":
			pemCert := []byte(rs.Primary.Attributes["certificate"])
			b, _ := pem.Decode(pemCert)
			if b == nil {
				return fmt.Errorf("error decoding PEM certificate")
			}

			rawCert = b.Bytes
		case "der":
			certAttr := rs.Primary.Attributes["certificate"]
			var err error
			rawCert, err = base64.StdEncoding.DecodeString(certAttr)
			if err != nil {
				return fmt.Errorf("error decoding der certificate: %w", err)
			}
		}

		crt, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("error parsing certificate: %w", err)
		}

		expectedMaxPathLen, err := strconv.Atoi(rs.Primary.Attributes["max_path_length"])
		if err != nil {
			return fmt.Errorf("error parsing max_path_length value as int: %w", err)
		}

		if expectedMaxPathLen != crt.MaxPathLen {
			return fmt.Errorf("expected MaxPathLen %d, actual %d", expectedMaxPathLen, crt.MaxPathLen)
		}

		if notAfter != "" {
			notAfterTime, err := time.Parse(time.RFC3339, notAfter)
			if err != nil {
				return fmt.Errorf("error parsing not_after value: %w", err)
			}

			if !notAfterTime.Equal(crt.NotAfter) {
				return fmt.Errorf("unexpected not_after in certificate: expected %s, got %s", notAfter, crt.NotAfter.Format(time.RFC3339))
			}
		}

		if expectedSignatureAlgorithm != crt.SignatureAlgorithm {
			return fmt.Errorf("expected signature algorithm (form signature_bits) %s, actual %s", expectedSignatureAlgorithm, crt.SignatureAlgorithm)
		}

		return nil
	}
}

func testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, path string, revoke bool, extra ...string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = vault_mount.test-root.type
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test-root.path
  type                 = "internal"
  common_name          = "RootOrg Root CA"
  ttl                  = "86400"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "Organizational Unit"
  organization         = "RootOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
  not_before_duration  = "240s"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on  = [vault_pki_secret_backend_root_cert.test]
  backend     = vault_mount.test-intermediate.path
  type        = "internal"
  common_name = "SubOrg Intermediate CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend              = vault_mount.test-root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name          = "SubOrg Intermediate CA"
  exclude_cn_from_sans = true
  ou                   = "SubUnit"
  organization         = "SubOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
  revoke               = %t
  max_path_length      = 0
  %s
}
`, rootPath, path, revoke, strings.Join(extra, "\n"))

	return config
}

func testPkiSecretBackendRootSignIntermediateConfig_name_constraints(rootPath, path, format string, revoke bool, issuerRef string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = vault_mount.test-root.type
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test-root.path
  type                 = "internal"
  common_name          = "RootOrg Root CA"
  ttl                  = "86400"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "Organizational Unit"
  organization         = "RootOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on  = [vault_pki_secret_backend_root_cert.test]
  backend     = vault_mount.test-intermediate.path
  type        = "internal"
  common_name = "SubOrg Intermediate CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend              = vault_mount.test-root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name          = "SubOrg Intermediate CA"
  exclude_cn_from_sans = true
  ou                   = "SubUnit"
  organization         = "SubOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
  permitted_dns_domains		= ["example.com",".example.com"]
  excluded_dns_domains		= ["bad.example.com"]
  permitted_ip_ranges		= ["192.0.2.0/24", "2001:db8::/32"]
  excluded_ip_ranges		= ["192.0.3.0/24", "2002:db8::/16"]
  permitted_email_addresses = ["admin@example.com","info@example.com"]
  excluded_email_addresses	= ["root@example.com"]
  permitted_uri_domains		= ["https://example.com", "https://www.example.com"]
  excluded_uri_domains		= ["ftp://example.com"]
  revoke               = %t
`, rootPath, path, revoke)

	if format != "" {
		config += fmt.Sprintf(`
  format = %q
`, format)
	}

	if issuerRef != "" {
		config += fmt.Sprintf(`
  issuer_ref = "%s"
`, issuerRef)
	}

	return config + "}"
}

func testPkiSecretBackendRootSignIntermediateConfig_signature_bits(rootPath, path, format string, signatureBits string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = vault_mount.test-root.type
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test-root.path
  type                 = "internal"
  common_name          = "RootOrg Root CA"
  ttl                  = "86400"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "Organizational Unit"
  organization         = "RootOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on  = [vault_pki_secret_backend_root_cert.test]
  backend     = vault_mount.test-intermediate.path
  type        = "internal"
  common_name = "SubOrg Intermediate CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend              = vault_mount.test-root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name          = "SubOrg Intermediate CA"
  exclude_cn_from_sans = true
  ou                   = "SubUnit"
  organization         = "SubOrg"
  country              = "US"
  locality             = "San Francisco"
  province             = "CA"
  signature_bits       = "%s"
`, rootPath, path, signatureBits)

	if format != "" {
		config += fmt.Sprintf(`
  format = %q
`, format)
	}
	return config + "}"
}

func testPkiSecretBackendRootSignIntermediateConfig_multiple_inter(rootPath, prePath, path, format string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds  = "8640000"
}

resource "vault_mount" "one" {
  path = "%s"
  type = vault_mount.root.type
  description = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds = "86400"
}

resource "vault_mount" "two" {
  path = "%s"
  type = vault_mount.one.type
  description = "test intermediate 2"
  default_lease_ttl_seconds = "28800"
  max_lease_ttl_seconds = "28800"
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend = vault_mount.root.path
  type = "internal"
  common_name = "RootOrg Root CA"
  ttl = "86400"
  format = "pem"
  private_key_format = "der"
  key_type = "rsa"
  key_bits = 4096
  exclude_cn_from_sans = true
  ou = "Organizational Unit"
  organization = "RootOrg"
  country = "US"
  locality = "San Francisco"
  province = "CA"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "one" {
	depends_on = [vault_pki_secret_backend_root_cert.root]
	backend = vault_mount.one.path
	type = "internal"
	common_name = "SubOrg Intermediate 1 CA"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "two" {
  depends_on = [vault_pki_secret_backend_root_cert.root]
  backend = vault_mount.two.path
  type = "internal"
  common_name = "SubOrg Intermediate 2 CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "one" {
  backend = vault_mount.root.path
  csr = vault_pki_secret_backend_intermediate_cert_request.one.csr
  common_name = "SubOrg Intermediate 1 CA"
  exclude_cn_from_sans = true
  ou = "SubUnit"
  organization = "SubOrg"
  country = "US"
  locality = "San Francisco"
  province = "CA"
	format = %q
}

resource "vault_pki_secret_backend_root_sign_intermediate" "two" {
	depends_on = [vault_pki_secret_backend_intermediate_set_signed.one]
	backend = vault_mount.one.path
	csr = vault_pki_secret_backend_intermediate_cert_request.two.csr
	common_name = "SubOrg Intermediate 2 CA"
	exclude_cn_from_sans = true
	ou = "SubUnit"
	organization = "SubOrg"
	country = "US"
	locality = "San Francisco"
	province = "CA"
	format = %q
}

resource "vault_pki_secret_backend_intermediate_set_signed" "one" {
	backend = vault_mount.one.path
	certificate = vault_pki_secret_backend_root_sign_intermediate.one.certificate_bundle
}

resource "vault_pki_secret_backend_intermediate_set_signed" "two" {
	backend = vault_mount.two.path
	certificate = vault_pki_secret_backend_root_sign_intermediate.two.certificate_bundle
}
	`, rootPath, prePath, path, format, format)

	return config
}

func Test_pkiSecretRootSignIntermediateRUpgradeV0(t *testing.T) {
	tests := []struct {
		name        string
		rawState    map[string]interface{}
		want        map[string]interface{}
		wantErr     bool
		expectedErr error
	}{
		{
			name: "basic",
			rawState: map[string]interface{}{
				"format":      "pem",
				"issuing_ca":  testPKICARoot,
				"certificate": testPKICAInter1,
				"ca_chain":    "",
			},
			want: map[string]interface{}{
				"format":      "pem",
				"issuing_ca":  testPKICARoot,
				"certificate": testPKICAInter1,
				"ca_chain": []string{
					testPKICARoot,
					testPKICAInter1,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid-no-issuing-ca",
			rawState: map[string]interface{}{
				"format":      "pem",
				"certificate": testPKICAInter1,
				"ca_chain":    "",
			},
			want:        nil,
			wantErr:     true,
			expectedErr: fmt.Errorf("required certificate for %q is missing or empty", "issuing_ca"),
		},
		{
			name: "invalid-no-certificate",
			rawState: map[string]interface{}{
				"format":     "pem",
				"issuing_ca": testPKICARoot,
				"ca_chain":   "",
			},
			want:        nil,
			wantErr:     true,
			expectedErr: fmt.Errorf("required certificate for %q is missing or empty", "certificate"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkiSecretRootSignIntermediateRUpgradeV0(nil, tt.rawState, nil)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("pkiSecretRootSignIntermediateRUpgradeV0() error = %#v, wantErr %#v", err, tt.wantErr)
				}

				if !reflect.DeepEqual(tt.expectedErr, err) {
					t.Errorf("pkiSecretRootSignIntermediateRUpgradeV0() expected %#v, actual %#v",
						tt.expectedErr, err)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkiSecretRootSignIntermediateRUpgradeV0() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_setCAChain(t *testing.T) {
	pem2derb64 := func(data string) string {
		b, _ := pem.Decode([]byte(data))
		return base64.StdEncoding.EncodeToString(b.Bytes)
	}

	derRootCert := pem2derb64(testPKICARoot)
	derInt1Cert := pem2derb64(testPKICAInter1)

	tests := []struct {
		resp      *api.Secret
		name      string
		format    string
		want      []interface{}
		wantErr   bool
		expectErr error
	}{
		{
			name:   "empty-ca-chain-pem",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": testPKICAInter1,
					"issuing_ca":  testPKICARoot,
					"ca_chain":    []interface{}{},
				},
			},
			want: []interface{}{
				testPKICARoot,
				testPKICAInter1,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-pem-bundle",
			format: "pem_bundle",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": testPKICAInter1,
					"issuing_ca":  testPKICARoot,
					"ca_chain":    []interface{}{},
				},
			},
			want: []interface{}{
				testPKICARoot,
				testPKICAInter1,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-2-pem",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": strings.Join(
						[]string{
							testPKICAInter2,
							testPKICAInter1,
							testPKICARoot,
						}, "\n"),
					"issuing_ca": testPKICAInter1,
					"ca_chain":   []interface{}{},
				},
			},
			want: []interface{}{
				testPKICAInter1,
				testPKICAInter2,
				testPKICARoot,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-2-duplicate-pem",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": strings.Join(
						[]string{
							testPKICAInter2,
							testPKICAInter1,
							testPKICAInter2,
							testPKICARoot,
						}, "\n"),
					"issuing_ca": testPKICAInter1,
					"ca_chain":   []interface{}{},
				},
			},
			want: []interface{}{
				testPKICAInter1,
				testPKICAInter2,
				testPKICARoot,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-2-pem-bundle",
			format: "pem_bundle",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": strings.Join(
						[]string{
							testPKICAInter2,
							testPKICAInter1,
							testPKICARoot,
						}, "\n"),
					"issuing_ca": testPKICAInter1,
					"ca_chain":   []interface{}{},
				},
			},
			want: []interface{}{
				testPKICAInter1,
				testPKICAInter2,
				testPKICARoot,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-2-duplicate-pem-bundle",
			format: "pem_bundle",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": strings.Join(
						[]string{
							testPKICAInter2,
							testPKICAInter1,
							testPKICAInter2,
							testPKICARoot,
						}, "\n"),
					"issuing_ca": testPKICAInter1,
					"ca_chain":   []interface{}{},
				},
			},
			want: []interface{}{
				testPKICAInter1,
				testPKICAInter2,
				testPKICARoot,
			},
			wantErr: false,
		},
		{
			name:   "empty-ca-chain-der",
			format: "der",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": derInt1Cert,
					"issuing_ca":  derRootCert,
					"ca_chain":    []interface{}{},
				},
			},
			want: []interface{}{
				derRootCert,
				derInt1Cert,
			},
			wantErr: false,
		},
		{
			name:   "absent-ca-chain-der",
			format: "der",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": derInt1Cert,
					"issuing_ca":  derRootCert,
				},
			},
			want: []interface{}{
				derRootCert,
				derInt1Cert,
			},
			wantErr: false,
		},
		{
			name:   "populated-ca-chain",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
					"issuing_ca":  "root-ca.crt",
					"ca_chain": []interface{}{
						testPKICARoot,
						testPKICAInter1,
					},
				},
			},
			want: []interface{}{
				testPKICARoot,
				testPKICAInter1,
			},
			wantErr: false,
		},
		{
			name:   "invalid-ca-chain-type",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
					"issuing_ca":  "root-ca.crt",
					"ca_chain":    "invalid-type",
				},
			},
			wantErr:   true,
			expectErr: fmt.Errorf("response contains an unexpected type string for %q", "ca_chain"),
			want:      []interface{}{},
		},
		{
			name:   "missing-intermediate-cert",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"issuing_ca": "root-ca.crt",
				},
			},
			want:      []interface{}{},
			wantErr:   true,
			expectErr: fmt.Errorf("required certificate for %q is missing or empty", "certificate"),
		},
		{
			name:   "missing-issuing-ca",
			format: "pem",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
				},
			},
			want:      []interface{}{},
			wantErr:   true,
			expectErr: fmt.Errorf("required certificate for %q is missing or empty", "issuing_ca"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(
				t,
				map[string]*schema.Schema{
					"format": {
						Type:     schema.TypeString,
						Required: true,
					},
					"ca_chain": {
						Type:     schema.TypeList,
						Required: false,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
				map[string]interface{}{
					"format": tt.format,
				})
			err := setCAChain(d, tt.resp)
			if tt.wantErr {
				if err == nil {
					t.Errorf("setCAChain() error = %v, wantErr %v", err, tt.wantErr)
				}
				if tt.expectErr != nil && !reflect.DeepEqual(tt.expectErr, err) {
					t.Errorf("setCAChain() expected error = %#v, actual %#v", err, tt.expectErr)
				}
			}

			actual := d.Get("ca_chain")
			if !reflect.DeepEqual(tt.want, actual) {
				t.Errorf("setCAChain() expected %#v, actual %#v", tt.want, actual)
			}
		})
	}
}
