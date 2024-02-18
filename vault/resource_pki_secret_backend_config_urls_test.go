// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigUrls_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	issuingCertificates := "http://127.0.0.1:8200/v1/pki/ca"
	crlDistributionPoints := "http://127.0.0.1:8200/v1/pki/crl"
	ocspServers := "http://127.0.0.1:8200/v1/pki/oscp"
	enableTemplating := false

	resourceType := "vault_pki_secret_backend_config_urls"
	resourceName := resourceType + ".test"
	getChecks := func(i, c, o string, e bool) resource.TestCheckFunc {
		baseChecks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttr(
				resourceName, "issuing_certificates.#", "1"),
			resource.TestCheckResourceAttr(
				resourceName, "issuing_certificates.0", i),
			resource.TestCheckResourceAttr(
				resourceName, "crl_distribution_points.#", "1"),
			resource.TestCheckResourceAttr(
				resourceName, "crl_distribution_points.0", c),
			resource.TestCheckResourceAttr(
				resourceName, "ocsp_servers.#", "1"),
			resource.TestCheckResourceAttr(
				resourceName, "ocsp_servers.0", o),
		}
		v114Checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttr(
				resourceName, "enable_templating", strconv.FormatBool(e)),
		}

		return func(state *terraform.State) error {
			var checks []resource.TestCheckFunc
			meta := testProvider.Meta().(*provider.ProviderMeta)
			checks = append(checks, baseChecks...)
			if provider.IsAPISupported(meta, provider.VaultVersion114) {
				checks = append(checks, v114Checks...)
			}

			return resource.ComposeTestCheckFunc(checks...)(state)
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				// Test that reading from an unconfigured mount succeeds
				Config: testPkiSecretBackendCertConfigUrlsMountConfig(rootPath),
				Check:  testPkiSecretBackendConfigUrlsEmptyRead,
			},
			{
				Config: testPkiSecretBackendCertConfigUrlsConfig(
					rootPath, issuingCertificates, crlDistributionPoints, ocspServers),
				Check: getChecks(
					issuingCertificates, crlDistributionPoints, ocspServers, enableTemplating),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return provider.IsAPISupported(meta, provider.VaultVersion114), nil
				},
				Config: testPkiSecretBackendCertConfigUrlsConfig(
					rootPath, issuingCertificates, crlDistributionPoints, ocspServers),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !provider.IsAPISupported(meta, provider.VaultVersion114), nil
				},
				Config: testPkiSecretBackendCertConfigUrlsConfig114(
					rootPath, issuingCertificates, crlDistributionPoints, ocspServers, enableTemplating),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testPkiSecretBackendCertConfigUrlsConfig114(
					rootPath, issuingCertificates+"/new", crlDistributionPoints+"/new", ocspServers+"/new", !enableTemplating),
				Check: getChecks(
					issuingCertificates+"/new", crlDistributionPoints+"/new", ocspServers+"/new", !enableTemplating),
			},
		},
	})
}

func testPkiSecretBackendConfigUrlsEmptyRead(s *terraform.State) error {
	paths, err := listPkiPaths(s)
	if err != nil {
		return err
	}
	for _, path := range paths {
		d := &schema.ResourceData{}
		d.SetId(path)
		if err := pkiSecretBackendConfigUrlsRead(d, testProvider.Meta()); err != nil {
			return err
		}
	}
	return nil
}

func listPkiPaths(s *terraform.State) ([]string, error) {
	var paths []string

	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_mount" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "pki" && path == rsPath {
				paths = append(paths, path)
			}
		}
	}

	return paths, nil
}

func testPkiSecretBackendCertConfigUrlsMountConfig(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = 8640000
  max_lease_ttl_seconds     = 8640000
}
`, rootPath)
}

func testPkiSecretBackendCertConfigUrlsConfig(rootPath string, issuingCertificates string, crlDistributionPoints string, ocspServers string) string {
	return fmt.Sprintf(`
%s

resource "vault_pki_secret_backend_config_urls" "test" {
  backend                 = vault_mount.test-root.path
  issuing_certificates    = ["%s"]
  crl_distribution_points = ["%s"]
  ocsp_servers            = ["%s"]
}
`,
		testPkiSecretBackendCertConfigUrlsMountConfig(rootPath),
		issuingCertificates, crlDistributionPoints, ocspServers)
}

func testPkiSecretBackendCertConfigUrlsConfig114(rootPath string, issuingCertificates string, crlDistributionPoints string, ocspServers string, enableTemplating bool) string {
	return fmt.Sprintf(`
%s

resource "vault_pki_secret_backend_config_urls" "test" {
  backend                 = vault_mount.test-root.path
  issuing_certificates    = ["%s"]
  crl_distribution_points = ["%s"]
  ocsp_servers            = ["%s"]
  enable_templating       = %t
}
`,
		testPkiSecretBackendCertConfigUrlsMountConfig(rootPath),
		issuingCertificates, crlDistributionPoints, ocspServers, enableTemplating)
}
