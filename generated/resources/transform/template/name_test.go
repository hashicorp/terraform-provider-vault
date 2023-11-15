// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	sdk_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/alphabet"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.UpdateSchemaResource(vault.MountResource(), false))
	p.RegisterResource("vault_transform_alphabet_name", vault.UpdateSchemaResource(alphabet.NameResource(), false))
	p.RegisterResource("vault_transform_template_name", vault.UpdateSchemaResource(NameResource(), false))
	return p
}()

func TestTemplateName(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": nameTestProvider.SchemaProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "regex",
					`(\\d{4})-(\\d{4})-(\\d{4})-(\\d{4})`,
					"numerics",
					"$1-$2-$3-$4",
					`{ "last-four" = "$4" }`,
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "pattern", `(\d{4})-(\d{4})-(\d{4})-(\d{4})`),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "alphabet", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "encode_format", "$1-$2-$3-$4"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "decode_formats.last-four", "$4"),
				),
			},
			{
				Config: basicConfig(path, "regex",
					`(\\d{9})`,
					"builtin/numeric",
					"",
					"",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "pattern", `(\d{9})`),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "alphabet", "builtin/numeric"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "encode_format", ""),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "decode_formats.#", "0"),
				),
			},
			{
				ResourceName:      "vault_transform_template_name.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func destroy(s *terraform.State) error {
	client := nameTestProvider.SchemaProvider().Meta().(*provider.ProviderMeta).GetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_template_name" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for alphabet %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("alphabet %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func basicConfig(path, tp, pattern, alphabet, encodeFormat, decodeFormats string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_alphabet_name" "numerics" {
  path = vault_mount.transform.path
  name = "numerics"
  alphabet = "0123456789"
}

resource "vault_transform_template_name" "test" {
  path = vault_transform_alphabet_name.numerics.path
  name = "ccn"
  type = "%s"`, path, tp)

	if pattern != "" {
		config += fmt.Sprintf(`
  pattern = "%s"`, pattern)
	}
	if alphabet != "" {
		config += fmt.Sprintf(`
  alphabet = "%s"`, alphabet)
	}
	if encodeFormat != "" {
		config += fmt.Sprintf(`
  encode_format = "%s"`, encodeFormat)
	}
	if decodeFormats != "" {
		config += fmt.Sprintf(`
  decode_formats = %s`, decodeFormats)
	}

	return config + "\n}\n"
}
