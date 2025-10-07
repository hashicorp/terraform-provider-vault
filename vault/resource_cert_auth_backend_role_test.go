// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_basic(backend, name, testCertificate, allowedNames, allowedOrgUnits),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "300"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "600"),
					resource.TestCheckResourceAttr(resourceName, "allowed_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_organizational_units.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_organizational_units.*", "foo"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_organizational_units.*", "baz"),
					testCertAuthBackendCheck_attrs(resourceName, backend, name),
				),
			},
			{
				Config: testCertAuthBackendConfig_unset(backend, name, testCertificate, allowedNames),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "allowed_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_organizational_units.#", "0"),
					testCertAuthBackendCheck_attrs(resourceName, backend, name),
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
			testutil.TestAccPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_OCSP_default(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPServersOverride+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPCACertificates, ""),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPEnabled, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPFailOpen, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPQueryAllServers, "false"),
				),
			},
			{
				Config: testCertAuthBackendConfig_OCSP_basic(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPServersOverride+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, fieldOCSPServersOverride+".*", "server1.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, fieldOCSPServersOverride+".*", "server2.com"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPCACertificates, testBase64PEM),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPFailOpen, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOCSPQueryAllServers, "true"),
				),
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
			"name":                         "display_name",
			"allowed_names":                "allowed_names",
			"allowed_dns_sans":             "allowed_dns_sans",
			"allowed_email_sans":           "allowed_email_sans",
			"allowed_uri_sans":             "allowed_uri_sans",
			"allowed_organizational_units": "allowed_organizational_units",
			"required_extensions":          "required_extensions",
			"certificate":                  "certificate",
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
			case TokenFieldPolicies, "allowed_names", "allowed_organizational_units":
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testCertAuthBackendConfig_basic(backend, name, certificate string, allowedNames, allowedOrgUnits []string) string {
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
}
`, backend, name, certificate, util.ArrayToTerraformList(allowedNames), util.ArrayToTerraformList(allowedOrgUnits))

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

    certificate = <<EOF
%s
EOF
}
`, backend, name, testBase64PEM, testCertificate)

	return config
}
