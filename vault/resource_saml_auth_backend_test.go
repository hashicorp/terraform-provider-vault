// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSAMLAuthBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("saml")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						fieldIDPMetadataURL, "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"),
					resource.TestCheckResourceAttr(resourceName,
						fieldEntityID, "https://my.vault/v1/auth/saml"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.0", "https://my.vault.primary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						fieldDefaultRole, "admin"),
				),
			},
			{
				Config: testAccSAMLAuthBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						fieldIDPMetadataURL, "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"),
					resource.TestCheckResourceAttr(resourceName,
						fieldEntityID, "https://my.vault/v1/auth/saml"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.#", "2"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.0", "https://my.vault.primary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.1", "https://my.vault.secondary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						fieldDefaultRole, "project-aqua-developers"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func testAccSAMLAuthBackendConfig_basic(path string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
}
`, path)
	return ret
}

func testAccSAMLAuthBackendConfig_updated(path string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback", "https://my.vault.secondary/v1/auth/saml/callback"]
  default_role     = "project-aqua-developers"
}
`, path)
	return ret
}
