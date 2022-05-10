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

func TestPkiSecretBackendRootCertificate_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_root_cert.test"

	store := &testPKICertStore{}

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", path),
		resource.TestCheckResourceAttr(resourceName, "type", "internal"),
		resource.TestCheckResourceAttr(resourceName, "common_name", "test Root CA"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "86400"),
		resource.TestCheckResourceAttr(resourceName, "format", "pem"),
		resource.TestCheckResourceAttr(resourceName, "private_key_format", "der"),
		resource.TestCheckResourceAttr(resourceName, "key_type", "rsa"),
		resource.TestCheckResourceAttr(resourceName, "key_bits", "4096"),
		resource.TestCheckResourceAttr(resourceName, "ou", "test"),
		resource.TestCheckResourceAttr(resourceName, "organization", "test"),
		resource.TestCheckResourceAttr(resourceName, "country", "test"),
		resource.TestCheckResourceAttr(resourceName, "locality", "test"),
		resource.TestCheckResourceAttr(resourceName, "province", "test"),
		resource.TestCheckResourceAttrSet(resourceName, "serial"),
		resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootCertificateDestroy,
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
					client := testProvider.Meta().(*api.Client)
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
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete(fmt.Sprintf("%s/root", path))
					if err != nil {
						t.Fatal(err)
					}
					genPath := pkiSecretBackendIntermediateSetSignedReadPath(path, "internal")
					resp, err := client.Logical().Write(genPath,
						map[string]interface{}{
							"common_name": "out-of-band",
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

func testPkiSecretBackendRootCertificateDestroy(s *terraform.State) error {
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
				"serial": "aa:bb:cc:dd:ee",
			},
			want: map[string]interface{}{
				"serial":        "aa:bb:cc:dd:ee",
				"serial_number": "aa:bb:cc:dd:ee",
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
