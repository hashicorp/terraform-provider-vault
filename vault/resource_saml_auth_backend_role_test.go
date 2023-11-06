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

func TestAccSAMLAuthBackendRole_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("saml")
	name := acctest.RandomWithPrefix("test-role")

	resourceType := "vault_saml_auth_backend_role"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProviderFactories: providerFactories,
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendRoleConfig_basic(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName,
						fieldBoundAttributesType, "string"),
					resource.TestCheckResourceAttr(resourceName,
						fieldBoundSubjectsType, "string"),

					resource.TestCheckResourceAttr(resourceName,
						"bound_subjects.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_subjects.0", "*example.com"),
					resource.TestCheckResourceAttr(resourceName,
						"token_policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"token_policies.0", "writer"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_attributes.%", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_attributes.group", "admin"),
					resource.TestCheckResourceAttr(resourceName,
						TokenFieldTTL, "86400"),
				),
			},
			{
				Config: testAccSAMLAuthBackendRoleConfig_updated(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName,
						fieldBoundAttributesType, "glob"),
					resource.TestCheckResourceAttr(resourceName,
						fieldBoundSubjectsType, "glob"),

					resource.TestCheckResourceAttr(resourceName,
						"bound_subjects.#", "2"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_subjects.0", "*example.com"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_subjects.1", "*hashicorp.com"),
					resource.TestCheckResourceAttr(resourceName,
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName,
						"token_policies.0", "reader"),
					resource.TestCheckResourceAttr(resourceName,
						"token_policies.1", "writer"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_attributes.%", "2"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_attributes.group", "admin,prod"),
					resource.TestCheckResourceAttr(resourceName,
						"bound_attributes.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName,
						TokenFieldTTL, "7200"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testAccSAMLAuthBackendRoleConfig_basic(path, name string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
}

resource "vault_saml_auth_backend_role" "test" {
  path                = vault_saml_auth_backend.test.path
  name                = "%s"
  groups_attribute    = "groups"
  bound_attributes    = {
    group = "admin"
  }
  bound_subjects      = ["*example.com"]
  token_policies      = ["writer"]
  token_ttl           = 86400
}
`, path, name)
	return ret
}

func testAccSAMLAuthBackendRoleConfig_updated(path, name string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
}

resource "vault_saml_auth_backend_role" "test" {
  path                  = vault_saml_auth_backend.test.path
  name                  = "%s"
  groups_attribute      = "groups"
  bound_attributes    = {
    group = "admin,prod"
    foo   = "bar"
  }
  bound_subjects        = ["*example.com", "*hashicorp.com"]
  bound_subjects_type   = "glob"
  bound_attributes_type = "glob"
  token_policies        = ["writer", "reader"]
  token_ttl             = "7200"
}
`, path, name)
	return ret
}
