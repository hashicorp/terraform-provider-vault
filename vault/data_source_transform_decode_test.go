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

func TestAccDecodeBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: transformDecode_basicConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_transform_decode.test", "decoded_value"),
				),
			},
		},
	})
}

func transformDecode_basicConfig(path string) string {
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

data "vault_transform_decode" "test" {
  path      = vault_transform_role.payments.path
  role_name = "payments"
  value     = "9300-3376-4943-8903"
}
`, path)
}

func TestAccDecodeBatch(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: transformDecode_batchConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transform_decode.test", "batch_results.#", "1"),
					resource.TestCheckResourceAttrSet("data.vault_transform_decode.test", "batch_results.0.decoded_value"),
				),
			},
		},
	})
}

func transformDecode_batchConfig(path string) string {
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

data "vault_transform_decode" "test" {
  path        = vault_transform_role.payments.path
  role_name   = "payments"
  batch_input = [{ "value" : "9300-3376-4943-8903" }]
}
`, path)
}
