// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccTransformTemplate(t *testing.T) {
	var p *schema.Provider
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testTransformTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransformTemplate_basicConfig(path, "regex",
					`(\\d{4})-(\\d{4})-(\\d{4})-(\\d{4})`,
					"numerics",
					"$1-$2-$3-$4",
					`{ "last-four" = "$4" }`,
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "pattern", `(\d{4})-(\d{4})-(\d{4})-(\d{4})`),
					resource.TestCheckResourceAttr("vault_transform_template.test", "alphabet", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "encode_format", "$1-$2-$3-$4"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "decode_formats.last-four", "$4"),
				),
			},
			{
				Config: testTransformTemplate_basicConfig(path, "regex",
					`(\\d{9})`,
					"builtin/numeric",
					"",
					"",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "pattern", `(\d{9})`),
					resource.TestCheckResourceAttr("vault_transform_template.test", "alphabet", "builtin/numeric"),
					resource.TestCheckResourceAttr("vault_transform_template.test", "encode_format", ""),
					resource.TestCheckResourceAttr("vault_transform_template.test", "decode_formats.#", "0"),
				),
			},
			{
				ResourceName:      "vault_transform_template.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransformTemplateDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_template" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

func testTransformTemplate_basicConfig(path, tp, pattern, alphabet, encodeFormat, decodeFormats string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_alphabet" "numerics" {
  path = vault_mount.transform.path
  name = "numerics"
  alphabet = "0123456789"
}

resource "vault_transform_template" "test" {
  path = vault_transform_alphabet.numerics.path
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
