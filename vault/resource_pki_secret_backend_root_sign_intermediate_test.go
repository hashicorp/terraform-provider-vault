package vault

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRootSignIntermediate_basic_default(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, ""),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem(t *testing.T) {
	path := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(path, intermediatePath, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", path, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_der(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	path := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "der"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, path, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem_bundle(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem_bundle"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, format),
			},
		},
	})
}

func testCheckPKISecretRootSignIntermediate(res, path, format string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(res, "backend", path),
		resource.TestCheckResourceAttr(res, "common_name", "SubOrg Intermediate CA"),
		resource.TestCheckResourceAttr(res, "ou", "SubUnit"),
		resource.TestCheckResourceAttr(res, "organization", "SubOrg"),
		resource.TestCheckResourceAttr(res, "country", "US"),
		resource.TestCheckResourceAttr(res, "locality", "San Francisco"),
		resource.TestCheckResourceAttr(res, "province", "CA"),
		resource.TestCheckResourceAttr(res, "format", format),
		resource.TestCheckResourceAttrSet(res, "serial"),
		assertPKICertificateBundle(res, format),
		assertPKICAChain(res),
	)
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
			expected = rs.Primary.Attributes["certificate"] + "\n" + rs.Primary.Attributes["issuing_ca"]
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

func testPkiSecretBackendRootSignIntermediateDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_mount" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "pki" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, path, format string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds  = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path = "%s"
  type = vault_mount.test-root.type
  description = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend = vault_mount.test-root.path
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

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on = [vault_pki_secret_backend_root_cert.test]
  backend = vault_mount.test-intermediate.path
  type = "internal"
  common_name = "SubOrg Intermediate CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend = vault_mount.test-root.path
  csr = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name = "SubOrg Intermediate CA"
  exclude_cn_from_sans = true
  ou = "SubUnit"
  organization = "SubOrg"
  country = "US"
  locality = "San Francisco"
  province = "CA"
`, rootPath, path)

	if format != "" {
		config += fmt.Sprintf(`
  format = %q
`, format)
	}

	return config + "}"
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
				"issuing_ca":  "issuing_ca.crt",
				"certificate": "intermediate_.crt",
				"ca_chain":    "",
			},
			want: map[string]interface{}{
				"issuing_ca":  "issuing_ca.crt",
				"certificate": "intermediate_.crt",
				"ca_chain":    []string{"issuing_ca.crt", "intermediate_.crt"},
			},
			wantErr: false,
		},
		{
			name: "invalid-no-issuing-ca",
			rawState: map[string]interface{}{
				"certificate": "intermediate_.crt",
				"ca_chain":    "",
			},
			want:        nil,
			wantErr:     true,
			expectedErr: fmt.Errorf("missing required field %q", "issuing_ca"),
		},
		{
			name: "invalid-no-certificate",
			rawState: map[string]interface{}{
				"issuing_ca": "issuing_ca.crt",
				"ca_chain":   "",
			},
			want:        nil,
			wantErr:     true,
			expectedErr: fmt.Errorf("missing required field %q", "certificate"),
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
