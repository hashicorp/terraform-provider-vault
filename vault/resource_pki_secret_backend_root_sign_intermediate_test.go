package vault

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRootSignIntermediate_basic_default(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, ""),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_der(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "der"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem_bundle(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())
	format := "pem_bundle"
	commonName := "SubOrg Intermediate CA"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.test", rootPath, commonName, format),
			},
		},
	})
}

func TestPkiSecretBackendRootSignIntermediate_basic_pem_bundle_multiple_intermediates(t *testing.T) {
	random := strconv.Itoa(acctest.RandInt())
	rootPath := "pki-root-" + random
	intermediate1Path := "pki-intermediate1-" + random
	intermediate2Path := "pki-intermediate2-" + random
	format := "pem_bundle"
	commonName := "SubOrg Intermediate 2 CA"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_multiple_inter(rootPath, intermediate1Path, intermediate2Path, format),
				Check:  testCheckPKISecretRootSignIntermediate("vault_pki_secret_backend_root_sign_intermediate.two", intermediate1Path, commonName, format),
			},
		},
	})
}

func testCheckPKISecretRootSignIntermediate(res, path, commonName, format string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(res, "backend", path),
		resource.TestCheckResourceAttr(res, "common_name", commonName),
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
			if strings.Count(rs.Primary.Attributes["certificate"], "-----BEGIN CERTIFICATE-----") >= 3 {
				expected = rs.Primary.Attributes["certificate"]
			} else {
				expected = rs.Primary.Attributes["certificate"] + "\n" + rs.Primary.Attributes["issuing_ca"]
			}
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
	t.Skip("Skip until VAULT-5425 is resolved")
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
			expectedErr: fmt.Errorf("required certificate for %q is missing or empty", "issuing_ca"),
		},
		{
			name: "invalid-no-certificate",
			rawState: map[string]interface{}{
				"issuing_ca": "issuing_ca.crt",
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
	t.Skip("Skip until VAULT-5425 is resolved")
	tests := []struct {
		resp      *api.Secret
		name      string
		want      []interface{}
		wantErr   bool
		expectErr error
	}{
		{
			name: "empty-ca-chain",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
					"issuing_ca":  "root-ca.crt",
					"ca_chain":    []interface{}{},
				},
			},
			want: []interface{}{
				"root-ca.crt",
				"intermediate-ca.crt",
			},
			wantErr: false,
		},
		{
			name: "absent-ca-chain",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
					"issuing_ca":  "root-ca.crt",
				},
			},
			want: []interface{}{
				"root-ca.crt",
				"intermediate-ca.crt",
			},
			wantErr: false,
		},
		{
			name: "populated-ca-chain",
			resp: &api.Secret{
				Data: map[string]interface{}{
					"certificate": "intermediate-ca.crt",
					"issuing_ca":  "root-ca.crt",
					"ca_chain": []interface{}{
						"resp-root-ca.crt",
						"resp-intermediate-ca.crt",
					},
				},
			},
			want: []interface{}{
				"resp-root-ca.crt",
				"resp-intermediate-ca.crt",
			},
			wantErr: false,
		},
		{
			name: "invalid-ca-chain-type",
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
			name: "missing-intermediate-cert",
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
			name: "missing-issuing-ca",
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
					"ca_chain": {
						Type:     schema.TypeList,
						Required: false,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
				map[string]interface{}{})
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
