// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const testCertificate = `
-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIJAIxJbvl6PnmvMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV
BAMTClZhdWx0IFRlc3QwHhcNMTgwNTA5MTcyMjU0WhcNMjgwNTA2MTcyMjU0WjAV
MRMwEQYDVQQDEwpWYXVsdCBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAxZj/1W69FiancHSEbMhfL0KZvftNksIN2rsMHhVkLDSn7KZyqlVhSOmy
gARFVmSwi5AO894FAuJU7L/RDcBD6mI3lTzDokeuRoRMpwbNg2aR+VNQaQpdHbLF
m3xTO1na7wuxO4F7tDzLQRKzO0wSmqBhXXdJsoTG97mA8Gq5tAR20Uz8vWh3PI8t
aFG6aSuL7rfm+O3iMoCPTj3DofUENfnd0ZxlXpR/X7Z1iQej5+jXIn0ygoXxc07r
fPd6J2jxz0lWL95Q65QWBSaKKNjWHaShSsqGe8KLZu9BFp20+M4Y8fd40B7+mlWk
17nUdqvwZtnNL1qf+t0SFFhueQY+4wIDAQABo3YwdDAdBgNVHQ4EFgQUoTWVof3Q
QakI0Xfamu5nJglXUwswRQYDVR0jBD4wPIAUoTWVof3QQakI0Xfamu5nJglXUwuh
GaQXMBUxEzARBgNVBAMTClZhdWx0IFRlc3SCCQCMSW75ej55rzAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQDFmMBq5s5vBHMrACXfgIBpZSSaiBXz8tVD
aiYO5UfZsWqEIn61+NrgJT4Xvhba3VZgGkOLX/9CfnTXx9nq4qL2ht4my2QszXXB
Jyi0pB+0VIQhbRzjbrYeQn8uCmN5DLph3sA+vJuUWvR7l6h1zUjzRrXWLFQ+qQxt
yYT18fgO3uttnbuzptDT23RDRySaoYLpeUFY47RIzFmuIO8bNsh8h5ymHNkVXrrv
vqDIxIPD/M21z4ZlZSbsokyVcsGKbF87xv8SFXj5GbtZ7UI0qVYr9zk/Y090Qv1a
ypM1k5jHWSBCixTrUFtWENQYLYhh2bMP1uJ4UMxSNJXCthRASqNF
-----END CERTIFICATE-----
`

const testKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxZj/1W69FiancHSEbMhfL0KZvftNksIN2rsMHhVkLDSn7KZy
qlVhSOmygARFVmSwi5AO894FAuJU7L/RDcBD6mI3lTzDokeuRoRMpwbNg2aR+VNQ
aQpdHbLFm3xTO1na7wuxO4F7tDzLQRKzO0wSmqBhXXdJsoTG97mA8Gq5tAR20Uz8
vWh3PI8taFG6aSuL7rfm+O3iMoCPTj3DofUENfnd0ZxlXpR/X7Z1iQej5+jXIn0y
goXxc07rfPd6J2jxz0lWL95Q65QWBSaKKNjWHaShSsqGe8KLZu9BFp20+M4Y8fd4
0B7+mlWk17nUdqvwZtnNL1qf+t0SFFhueQY+4wIDAQABAoIBAQCVeW/OXL7dCtCO
2RVz1P9sGM2EUZ4U7obcd7Jq73OfnRWKhz8mav/00BQfkxuAhxql+IvXHpRb4iqs
DU5vQIofu7ygQB8dm2vSHDKABz1fsS+rk8K4MwbNeHbTb/DmbMqZGhcwFHsnlPWM
fEDpElrgbYI52gr96EM7EjDfrVxdN83BLIHNki3OPDDMLAGkQV1wj6f9eNW/7QuU
Ryr9G7627mRi1tzu1W2ZfraiOY53TK6kDaa7tlxHYrh10O8lnblhfgkfQd6XIP09
IU52A6nZC+DifpM3S1NRl+WAXKzQsc/NR/6rrZB7so+5v7axHQLpGVoiRCUFcboS
5M5hnFhBAoGBAPUYgWTcu01CMrdCBZKm5UjAE6TKLYQrEF429HX81Q1UqO0c5ck0
KghUUtXCr/XGmsfPItbU4IlUutcpkd0DoKhTXLOvlshvtFUqVGa+HLQ3ZjyKJDCe
b+6RcYBFYjguQ6ToKvVbEMj9fkgWtOkwx8mcwxbFsTr2Nx20ZBUGYWiPAoGBAM5j
hOVddE21kbcrj3YKYwFykh7V+KgYMiAlm1lwDDLEKoEpZe6iCdE6/2eWgRHOtZgZ
qV7Pk69EdxSSI90N53CxDWvxs7xn4cvaX7tG8v5D/RJt8wToRwhBtSetvE6+ZxbO
Ov+I0j8mGYYVViIBQXNjc690NGhQlUSIxl1MQKZtAoGBAL3OcX5r1n15U49KCMjO
iOfzIANRMziUpQNhaaXp3BCLzJp785QC2r5ClzfFosEiQgGU7vUSPKT9wggYwEY5
pfRVQohA5fNpVm1R77T1a4NBF+KwVGB2glZtuklM8khxw5700Tfbgz8z2NT5CLdC
OKZwyUBcbukrffl6FruVimAPAoGAXw1YfGYxFUUFKi4GsV+RP25ru4XiMlCKbWHE
jUlcZNkRllDhoCjCirk4PZYENZZU7gsLhR3mr3bBvRidKcaoi68PNmKn26KgTElz
g4XmjZH0cNNwdBch97yDWRXbvwxT4B308BEse2bppGYZOCoJ4cGw2uKS7GQIivrP
GNLwh3UCgYBxkjgtvW3aH5/kdhEsggKFnmNPDkBGu1MDEEz5z+Z2w6jl18YyjgRj
HEjFCHzrCXzNp6fstSVLUXtvsbCtqTxj/XcBRkTMJqJBW9Xfh9nQbSKF6Hnudhle
bwvTJuiSbAHkhG+eM/04PpWPMo6skek10KmIBvGveHM8R89gbA1Fgw==
-----END RSA PRIVATE KEY-----
`

const testBase64PEM = `MIIDIzCCAgugAwIBAgIJAIxJbvl6PnmvMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMTClZhdWx0IFRlc3QwHhcNMTgwNTA5MTcyMjU0WhcNMjgwNTA2MTcyMjU0WjAVMRMwEQYDVQQDEwpWYXVsdCBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZj/1W69FiancHSEbMhfL0KZvftNksIN2rsMHhVkLDSn7KZyqlVhSOmygARFVmSwi5AO894FAuJU7L/RDcBD6mI3lTzDokeuRoRMpwbNg2aR+VNQaQpdHbLFm3xTO1na7wuxO4F7tDzLQRKzO0wSmqBhXXdJsoTG97mA8Gq5tAR20Uz8vWh3PI8taFG6aSuL7rfm+O3iMoCPTj3DofUENfnd0ZxlXpR/X7Z1iQej5+jXIn0ygoXxc07rfPd6J2jxz0lWL95Q65QWBSaKKNjWHaShSsqGe8KLZu9BFp20+M4Y8fd40B7+mlWk17nUdqvwZtnNL1qf+t0SFFhueQY+4wIDAQABo3YwdDAdBgNVHQ4EFgQUoTWVof3QQakI0Xfamu5nJglXUwswRQYDVR0jBD4wPIAUoTWVof3QQakI0Xfamu5nJglXUwuhGaQXMBUxEzARBgNVBAMTClZhdWx0IFRlc3SCCQCMSW75ej55rzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQDFmMBq5s5vBHMrACXfgIBpZSSaiBXz8tVDaiYO5UfZsWqEIn61+NrgJT4Xvhba3VZgGkOLX/9CfnTXx9nq4qL2ht4my2QszXXBJyi0pB+0VIQhbRzjbrYeQn8uCmN5DLph3sA+vJuUWvR7l6h1zUjzRrXWLFQ+qQxtyYT18fgO3uttnbuzptDT23RDRySaoYLpeUFY47RIzFmuIO8bNsh8h5ymHNkVXrrvvqDIxIPD/M21z4ZlZSbsokyVcsGKbF87xv8SFXj5GbtZ7UI0qVYr9zk/Y090Qv1aypM1k5jHWSBCixTrUFtWENQYLYhh2bMP1uJ4UMxSNJXCthRASqNF`

func TestCertAuthBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-cert-auth")
	name := acctest.RandomWithPrefix("tf-test-cert-name")

	allowedNames := []string{
		acctest.RandomWithPrefix("tf-ident-1"),
		acctest.RandomWithPrefix("tf-ident-2"),
	}

	allowedOrgUnits := []string{"foo", "baz"}

	resourceName := "vault_cert_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_basic(backend, name, testCertificate, "", allowedNames, allowedOrgUnits),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "300"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".*", "foo"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".*", "baz"),
					testCertAuthBackendCheck_attrs(resourceName, backend, name),
				),
			},
			{
				Config: testCertAuthBackendConfig_unset(backend, name, testCertificate, allowedNames),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".#", "0"),
					testCertAuthBackendCheck_attrs(resourceName, backend, name),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsAPISupported(provider.VaultVersion121) {
						return true, nil
					}

					return !meta.IsEnterpriseSupported(), nil
				},
				Config: testCertAuthBackendConfig_basic(backend, name, testCertificate, aliasMetadataConfig, allowedNames, allowedOrgUnits),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "300"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".*", "foo"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrganizationalUnits+".*", "baz"),
					testCertAuthBackendCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, FieldAliasMetadata+".%", "1"),
					resource.TestCheckResourceAttr(resourceName, FieldAliasMetadata+".foo", "bar"),
				),
			},
		},
	})
}

func TestCertAuthBackend_OCSP(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-cert-auth")
	name := acctest.RandomWithPrefix("tf-test-cert-name")

	resourceName := "vault_cert_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_OCSP_default(backend, name),
				Check: func() resource.TestCheckFunc {
					checks := []resource.TestCheckFunc{
						resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
						resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPServersOverride+".#", "0"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPCACertificates, ""),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPEnabled, "false"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPFailOpen, "false"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPQueryAllServers, "false"),
					}

					// These fields are only available from Vault 1.16+
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if meta.IsAPISupported(provider.VaultVersion116) {
						checks = append(checks,
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPMaxRetries, "4"),
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPThisUpdateMaxAge, "0"),
						)
					}

					return resource.ComposeTestCheckFunc(checks...)
				}(),
			},
			{
				Config: testCertAuthBackendConfig_OCSP_basic(backend, name),
				Check: func() resource.TestCheckFunc {
					checks := []resource.TestCheckFunc{
						resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
						resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPServersOverride+".#", "2"),
						resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldOCSPServersOverride+".*", "server1.com"),
						resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldOCSPServersOverride+".*", "server2.com"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPCACertificates, testBase64PEM),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPEnabled, "true"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPFailOpen, "true"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPQueryAllServers, "true"),
					}

					// These fields are only available from Vault 1.16+
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if meta.IsAPISupported(provider.VaultVersion116) {
						checks = append(checks,
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPMaxRetries, "5"),
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPThisUpdateMaxAge, "7200"),
						)
					}

					return resource.ComposeTestCheckFunc(checks...)
				}(),
			},
			{
				Config: testCertAuthBackendConfig_OCSP_field_update(backend, name),
				Check: func() resource.TestCheckFunc {
					checks := []resource.TestCheckFunc{
						resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
						resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPEnabled, "true"),
					}

					// These fields are only available from Vault 1.16+
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if meta.IsAPISupported(provider.VaultVersion116) {
						checks = append(checks,
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPMaxRetries, "10"),
							resource.TestCheckResourceAttr(resourceName, consts.FieldOCSPThisUpdateMaxAge, "3600"),
						)
					}

					return resource.ComposeTestCheckFunc(checks...)
				}(),
			},
		},
	})
}

func TestCertAuthBackend_OCSP_Negative(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-cert-auth")
	name := acctest.RandomWithPrefix("tf-test-cert-name")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				// Negative ocsp_max_retries should be rejected by Vault API
				Config:      testCertAuthBackendConfig_OCSP_negative_fields(backend, name, -1, 7200),
				ExpectError: regexp.MustCompile("ocsp_max_retries can not be a negative number"),
			},
			{
				// Negative ocsp_this_update_max_age should also be rejected by Vault API
				Config:      testCertAuthBackendConfig_OCSP_negative_fields(backend, name, 5, -100),
				ExpectError: regexp.MustCompile("cannot provide negative value"),
			},
		},
	})
}

func testCertAuthBackendDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_cert_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for Cert auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Cert auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testCertAuthBackendCheck_attrs(resourceName, backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		endpoint := "auth/" + strings.Trim(backend, "/") + "/certs/" + name
		if endpoint != path {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, path)
		}

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(backend, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "cert" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		attrs := map[string]string{
			consts.FieldName:                       consts.FieldDisplayName,
			consts.FieldAllowedNames:               consts.FieldAllowedNames,
			consts.FieldAllowedDNSSans:             consts.FieldAllowedDNSSans,
			consts.FieldAllowedEmailSans:           consts.FieldAllowedEmailSans,
			consts.FieldAllowedURISans:             consts.FieldAllowedURISans,
			consts.FieldAllowedOrganizationalUnits: consts.FieldAllowedOrganizationalUnits,
			consts.FieldRequiredExtensions:         consts.FieldRequiredExtensions,
			consts.FieldCertificate:                consts.FieldCertificate,
		}

		for _, v := range commonTokenFields {
			attrs[v] = v
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}
			switch k {
			case TokenFieldPolicies, consts.FieldAllowedNames, consts.FieldAllowedOrganizationalUnits:
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testCertAuthBackendConfig_basic(backend, name, certificate, extraConfig string, allowedNames, allowedOrgUnits []string) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = "%s"
    certificate   = <<EOF
%s
EOF
    allowed_names                = %s
    backend                      = vault_auth_backend.cert.path
    token_ttl                    = 300
    token_max_ttl                = 600
    token_policies               = ["test_policy_1", "test_policy_2"]
    allowed_organizational_units = %s
	%s
}
`, backend, name, certificate, util.ArrayToTerraformList(allowedNames), util.ArrayToTerraformList(allowedOrgUnits), extraConfig)

	return config
}

func testCertAuthBackendConfig_unset(backend, name, certificate string, allowedNames []string) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = "%s"
    certificate   = <<__CERTIFICATE__
%s
__CERTIFICATE__
    allowed_names  = %s
    backend        = vault_auth_backend.cert.path
}
`, backend, name, certificate, util.ArrayToTerraformList(allowedNames),
	)

	return config
}

func testCertAuthBackendConfig_OCSP_default(backend, name string) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name                   = "%s"
    backend                = vault_auth_backend.cert.path

    certificate = <<EOF
%s
EOF
}
`, backend, name, testCertificate)

	return config
}

func testCertAuthBackendConfig_OCSP_basic(backend, name string) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name                   = "%s"
    backend                = vault_auth_backend.cert.path
    ocsp_ca_certificates   = "%s"
    ocsp_enabled           = true
    ocsp_fail_open         = true
    ocsp_query_all_servers = true
    ocsp_servers_override  = ["server1.com", "server2.com"]
	ocsp_max_retries       = 5
	ocsp_this_update_max_age = 7200
    certificate = <<EOF
%s
EOF
}
`, backend, name, testBase64PEM, testCertificate)

	return config
}

func testCertAuthBackendConfig_OCSP_field_update(backend, name string) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name                      = "%s"
    backend                   = vault_auth_backend.cert.path
	ocsp_ca_certificates   = "%s"
    ocsp_enabled              = true
	ocsp_fail_open         = true
    ocsp_query_all_servers = true
	ocsp_servers_override  = ["server1.com", "server2.com"]
    ocsp_max_retries          = 10
    ocsp_this_update_max_age  = 3600

    certificate = <<EOF
%s
EOF
}
`, backend, name, testBase64PEM, testCertificate)

	return config
}

func testCertAuthBackendConfig_OCSP_negative_fields(backend, name string, maxRetries, maxAge int) string {
	config := fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name                      = "%s"
    backend                   = vault_auth_backend.cert.path
	ocsp_ca_certificates   = "%s"
    ocsp_enabled              = true
    ocsp_max_retries          = %d
    ocsp_this_update_max_age  = %d

    certificate = <<EOF
%s
EOF
}
`, backend, name, testBase64PEM, maxRetries, maxAge, testCertificate)

	return config
}
