package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestLDAPAuthBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-path")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_basic(path, "false"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
			{
				ResourceName:            "vault_ldap_auth_backend.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"bindpass"},
			},
		},
	})
}

func TestLDAPAuthBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-path")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "false"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
		},
	})
}

func TestLDAPAuthBackend_tls(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-ldap-tls-path")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_tls(path, "true"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "false"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "true"),
				Check:  testLDAPAuthBackendCheck_attrs(path),
			},
		},
	})
}

func testLDAPAuthBackendDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendCheck_attrs(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_ldap_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := strings.Trim(path, "/")
		if endpoint != instanceState.ID {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, instanceState.ID)
		}

		client := testProvider.Meta().(*api.Client)
		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(path, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", path)
		}

		if "ldap" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		if instanceState.Attributes["accessor"] != authMount.Accessor {
			return fmt.Errorf("accessor in state %s does not match accessor returned from vault %s", instanceState.Attributes["accessor"], authMount.Accessor)
		}

		configPath := "auth/" + endpoint + "/config"

		resp, err := client.Logical().Read(configPath)
		if err != nil {
			return err
		}

		// Check that `bindpass`, if present in the state, is not returned by the API
		if instanceState.Attributes["bindpass"] != "" && resp.Data["bindpass"] != nil {
			return fmt.Errorf("expected api field bindpass to not be returned, but was %q", resp.Data["bindpass"])
		}

		// Check that `client_tls_crt`, if present in the state, is not returned by the API
		if instanceState.Attributes["client_tls_crt"] != "" && resp.Data["client_tls_crt"] != nil {
			return fmt.Errorf("expected api field client_tls_crt to not be returned, but was %q", resp.Data["client_tls_crt"])
		}

		// Check that `client_tls_key`, if present in the state, is not returned by the API
		if instanceState.Attributes["client_tls_key"] != "" && resp.Data["client_tls_key"] != nil {
			return fmt.Errorf("expected api field client_tls_key to not be returned, but was %q", resp.Data["client_tls_key"])
		}

		attrs := map[string]string{
			"url":              "url",
			"starttls":         "starttls",
			"tls_min_version":  "tls_min_version",
			"tls_max_version":  "tls_max_version",
			"insecure_tls":     "insecure_tls",
			"certificate":      "certificate",
			"binddn":           "binddn",
			"userdn":           "userdn",
			"userattr":         "userattr",
			"discoverdn":       "discoverdn",
			"deny_null_bind":   "deny_null_bind",
			"upndomain":        "upndomain",
			"groupfilter":      "groupfilter",
			"groupdn":          "groupdn",
			"groupattr":        "groupattr",
			"use_token_groups": "use_token_groups",
		}

		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected api field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}

			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}
					for i := 0; i < count; i++ {
						stateData := instanceState.Attributes[stateAttr+"."+strconv.Itoa(i)]
						if stateData != apiData[i] {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be %q, got %q", i, apiAttr, stateAttr, endpoint, stateData, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]

			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}

		}

		return nil
	}
}

func testLDAPAuthBackendConfig_basic(path, use_token_groups string) string {

	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path                   = "%s"
    url                    = "ldaps://example.org"
    starttls               = true
    tls_min_version        = "tls11"
    tls_max_version        = "tls12"
    insecure_tls           = false
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    discoverdn             = false
    deny_null_bind         = true
    description            = "example"

    use_token_groups = %s
}
`, path, use_token_groups)

}

func testLDAPAuthBackendConfig_tls(path, use_token_groups string) string {

	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path                   = "%s"
    url                    = "ldaps://example.org"
    starttls               = true
    tls_min_version        = "tls11"
    tls_max_version        = "tls12"
    insecure_tls           = false
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    discoverdn             = false
    deny_null_bind         = true
    description            = "example"
    certificate            = <<EOT
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUahce2sCO7Bom/Rznd5HsNAlr1NgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODEyMDIwMTAxNDRaFw00NjEy
MTUwMTAxNDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDC8Qd4kJecWCLzysTV1NfoUd0E8rTBKN52HTLBWcJn
EtZsG//k/K2NNwI92t9buDax9s/A6B79YXdfYp5hI/xLFkDRzObPpAOyl4b3bUmR
la3Knmj743SV4tMhQCGrff2nc7WicA5Q7WTiwd+YLB+sOlOfaFzHhRFrk/PNvV8e
KC6yMgfWZwZ2dxoDpnYLM7XDgTyQ85S6QgOtxlPh9o5mtZQhBkpDDYnNPIon5kwM
JmrZMXNbCkvd4bjzAHsnuaJsVD/2cW/Gkh+UGMMBnxCKqTBivk3QM2xPFx9MJJ65
t8kMJR8hbAVmEuK3PA7FrNrNRApdf9I8xDWX8v2jeecfAgMBAAGjUzBRMB0GA1Ud
DgQWBBQXGfrns8OqxTGKsXG5pDZS/WyyYDAfBgNVHSMEGDAWgBQXGfrns8OqxTGK
sXG5pDZS/WyyYDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCt
8aUX26cl2PgdIEByZSHAX5G+2b0IEtTclPkl4uDyyKRY4dVq6gK3ueVSU5eUmBip
JbV5aRetovGOcV//8vbxkZm/ntQ8Oo+2sfGR5lIzd0UdlOr5pkD6g3bFy/zJ+4DR
DAe8fklUacfz6CFmD+H8GyHm+fKmF+mjr4oOGQW6OegRDJHuiipUk2lJyuXdlPSa
FpNRO2sGbjn000ANinFgnFiVzGDnx0/G1Kii/6GWrI6rrdVmXioQzF+8AloWckeB
+hbmbwkwQa/JrLb5SWcBDOXSgtn1Li3XF5AQQBBjA3pOlyBXqnI94Irw89Lv9uPT
MUR4qFxeUOW/GJGccMUd
-----END CERTIFICATE-----
EOT
    client_tls_cert        = <<EOT
-----BEGIN CERTIFICATE-----
MIID3jCCAsagAwIBAgIUFQKX5kCu6lBK60jF6HYPZH0v9oIwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTA2MDkwOTAzMDdaFw0zMTA2
MDcwOTAzMDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDRCYt5o89zZnQY65bC2sohOgEJa7CrLyPo4/2B/elC
UN7lGSH3NA/kAGIR6ZHl7pOTiXFfvTjkLdpp7IXw2YI/D/tfyYFp5OeO6GxQdrpp
0ctNia9mektigzNkiTXcWi0f3ye9TfKYP2ThJfHjua/2kYsVKtgCGZjou+qShKhm
KFNjIUMXf+1tyQmVu26pVc5OjnBETVyrJqZSbPSEoI0sDb231rsQN/NV5/tbtxDC
4ywm60bpgaqpIrhip1swp3XYn3CSfjGtzJuv9xMTJQ+bbS6A5Sncy+I69qlxbgwr
P7ny60xp2quT18qHQwH93fKbBypO4QfFlULogWkYw1nNAgMBAAGjgcUwgcIwCQYD
VR0TBAIwADARBglghkgBhvhCAQEEBAMCBaAwMwYJYIZIAYb4QgENBCYWJE9wZW5T
U0wgR2VuZXJhdGVkIENsaWVudCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU84RskljZ
wD5J+rinRsA4eykTS+owHwYDVR0jBBgwFoAUFxn657PDqsUxirFxuaQ2Uv1ssmAw
DgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAN
BgkqhkiG9w0BAQsFAAOCAQEANPokK0qpj1/b0hSrjImz1XD1N4QTKn47hV6hBhgr
6MYKwBRVj8e0Ly/qgmipprP8hQsBtZPaUh98ZXu9dI5br7jPD/NKv9EpFVHAHWxP
a4xuw2ibp4MdDSSsLxwV91KE/unoka1RjFZO6aLT+yS9Fkzyov5mWHh56nYdnpnv
ATFy+UpXn9+16ddPBGALGlOmDaEHWImMEc2dIN6/GvtOpmUD/cr7fbsIN8leRgzZ
suX9kmcMCISHk6aa5gWcRIBWPwxANNHUDL/+A6KAo36zM/dx8vln9XhftSEnxSFw
6Z5nUoT9l/5TSGwK/AIkS4ApBDOytf/YiAq01QR9ENRGRQ==
-----END CERTIFICATE-----
EOT
    client_tls_key         = <<EOT
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0QmLeaPPc2Z0GOuWwtrKIToBCWuwqy8j6OP9gf3pQlDe5Rkh
9zQP5ABiEemR5e6Tk4lxX7045C3aaeyF8NmCPw/7X8mBaeTnjuhsUHa6adHLTYmv
ZnpLYoMzZIk13FotH98nvU3ymD9k4SXx47mv9pGLFSrYAhmY6LvqkoSoZihTYyFD
F3/tbckJlbtuqVXOTo5wRE1cqyamUmz0hKCNLA29t9a7EDfzVef7W7cQwuMsJutG
6YGqqSK4YqdbMKd12J9wkn4xrcybr/cTEyUPm20ugOUp3MviOvapcW4MKz+58utM
adqrk9fKh0MB/d3ymwcqTuEHxZVC6IFpGMNZzQIDAQABAoIBAQCdi1UMM1KZheEA
Gya/6sembSH06K35BolI7/PTMfvIWEz1W5DGz/0d+M/w8hlcsweUjWTeJC2pg4l2
haWZFUVdo/zvf15C4htHEJL5vdHXCR/xa1C/qnIAaCOmpObsESarO7OmsAWjizvL
mJ6K5BrjeWPaazTruEEPPvmWvdZxTpx/vmnwnB8fhHdtMbkSCAqCyc/fUqJgAGLU
1QXFeTcasW39jtAdutJq98UR2yOYiknU7xwDUAALwcVM14p4GmsBUM8Sf5JbYK2c
EoBJk/aDJiK+fLgRinH76FNpTknvdH3hGfwotXwanSBKj3DzAQwY3JWXC5kIFdcL
HjhtiOjhAoGBAOfetKHANyFgWwiVdRLmUA42K1r/1yvrisKycxJl4HeYI27VsQNI
ffOLMkxLj8ahuXlzlceXUDvf78gkwydk8UGCvpFt1+da79rKfCGVogeNUmaExKke
+uFEoOrjWqaxtE/gRYmZlES9dhSnGQZH+r/V5HhxHrQI0MgAAITFMstZAoGBAObK
jLl6ShwYG9A97howUxJRaGmyTk3iMMzu1cKoP4OGCFrsYnaiG/dK/b85stz/55ks
aZjUR3anpUyedIo1DiB/Iqq0ues2UIo+adUno9Fyf+aI8x+gs4fsdbn8TXBMTPgC
XQxm+wsC2EKIB6IlttZRTdhvLOHiw5/PkoApnheVAoGBANwtRikydSdkcA0+nuVL
fkmAdrr6pkA2cpVfDpYx12y5MyxUDrqnY7KYQzLfra9Yct85OslEjhPNGcxb3FTU
LaOfm4ZNX+95EroX/LeHd0zkjZJ8EKLnoCO5H3TsX3Ba3nXa6S04gOqlXjNOWRz1
zM3NNh6IjDc5B8hi+BsbhphBAoGAfXgOi2N1WNKuhEa25FvzPZkuZ4/9TBA1MaSC
Z8IqTWmXrz6lxRMamxWU39oRaF5jXX2spt55P4OitQXMG7r+RCJ6CU4ZaUts+8s0
pCJZyCs0Z3N6oW4vTCz8T7FftDZ2/bnjNjPiNTlFst3bMIbKYLdw18KRJviuG3qw
jaaSgQUCgYEAhPaS+90L+Y01mDPH+adkhCYy4hoZlF2cOf0DJFzQ2CdNkoK1Cv9V
pIth9roSSN2mcYxH5P7uVIFm7jJ3tI4ExQdtJkPed/GK1DC7l2VGOi+TtCdm004r
MvQzNd87hRypUZ9Hyx2C9RljNDHHjgwYwWv9JOT0xEOS4ZAaPfvTf20=
-----END RSA PRIVATE KEY-----
EOT
    use_token_groups = %s
}
`, path, use_token_groups)

}
