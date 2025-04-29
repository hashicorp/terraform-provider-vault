// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccEncodeBasic(t *testing.T) {
	var p *schema.Provider
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: transformEncode_basicConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_transform_encode.test", "encoded_value"),
				),
			},
		},
	})
}

func transformEncode_basicConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "ccn-fpe" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe.path
  name            = "payments"
  transformations = [vault_transform_transformation.ccn-fpe.name]
}

data "vault_transform_encode" "test" {
  path      = vault_transform_role.payments.path
  role_name = "payments"
  value     = "1111-2222-3333-4444"
}
`, path)
}

func TestAccEncodeBatch(t *testing.T) {
	var p *schema.Provider
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: transformEncodeRole_batchConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transform_encode.test", "batch_results.#", "1"),
					resource.TestCheckResourceAttrSet("data.vault_transform_encode.test", "batch_results.0.encoded_value"),
				),
			},
		},
	})
}

func transformEncodeRole_batchConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "ccn-fpe" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe.path
  name            = "payments"
  transformations = [vault_transform_transformation.ccn-fpe.name]
}

data "vault_transform_encode" "test" {
  path        = vault_transform_role.payments.path
  role_name   = "payments"
  batch_input = [{ "value" : "1111-2222-3333-4444" }]
}
`, path)
}
