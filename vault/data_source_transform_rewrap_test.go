// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"go.uber.org/atomic"
)

func TestAccRewrapBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: transformRewrap_basicConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_transform_rewrap.rewrapped", "encoded_value"),
					testCheckResourceAttrDifferent(
						"data.vault_transform_encode.encoded", "encoded_value",
						"data.vault_transform_rewrap.rewrapped", "encoded_value",
					),
				),
			},
		},
	})
}

func testCheckResourceAttrDifferent(name1, key1, name2, key2 string) resource.TestCheckFunc {
	var value *atomic.String
	check := func(v string) error {
		if value == nil {
			value = atomic.NewString(v)
			return nil
		}
		if value.Load() == v {
			return fmt.Errorf("expected %s.%s (%q) to differ from %s.%s (%q)",
				name1, key1, value.Load(), name2, key2, v)
		}
		return nil
	}
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrWith(name1, key1, check),
		resource.TestCheckResourceAttrWith(name2, key2, check),
	)
}

func transformRewrap_basicConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "ccn-fpe-src" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe-src"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_transformation" "ccn-fpe-dst" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe-dst"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe-src.path
  name            = "payments"
  transformations = [vault_transform_transformation.ccn-fpe-src.name, vault_transform_transformation.ccn-fpe-dst.name]
}

data "vault_transform_encode" "encoded" {
  path           = vault_transform_role.payments.path
  role_name      = "payments"
  transformation = vault_transform_transformation.ccn-fpe-src.name
  value          = "1111-2222-3333-4444"
}

data "vault_transform_rewrap" "rewrapped" {
  path                  = vault_transform_role.payments.path
  role_name             = "payments"
  transformation        = vault_transform_transformation.ccn-fpe-dst.name
  decode_transformation = vault_transform_transformation.ccn-fpe-src.name
  value                 = data.vault_transform_encode.encoded.encoded_value
}
`, path)
}

func TestAccRewrapBatch(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: transformRewrap_batchConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transform_rewrap.rewrapped", "batch_results.#", "1"),
					resource.TestCheckResourceAttrSet("data.vault_transform_rewrap.rewrapped", "batch_results.0.encoded_value"),
					testCheckResourceAttrDifferent(
						"data.vault_transform_encode.encoded", "encoded_value",
						"data.vault_transform_rewrap.rewrapped", "batch_results.0.encoded_value",
					),
				),
			},
		},
	})
}

func transformRewrap_batchConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "ccn-fpe-src" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe-src"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_transformation" "ccn-fpe-dst" {
  path             = vault_mount.transform.path
  name             = "ccn-fpe-dst"
  type             = "fpe"
  template         = "builtin/creditcardnumber"
  tweak_source     = "internal"
  allowed_roles    = ["payments"]
  deletion_allowed = true
}

resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe-src.path
  name            = "payments"
  transformations = [vault_transform_transformation.ccn-fpe-src.name, vault_transform_transformation.ccn-fpe-dst.name]
}

data "vault_transform_encode" "encoded" {
  path           = vault_transform_role.payments.path
  role_name      = "payments"
  transformation = vault_transform_transformation.ccn-fpe-src.name
  value          = "1111-2222-3333-4444"
}

data "vault_transform_rewrap" "rewrapped" {
  path      = vault_transform_role.payments.path
  role_name = "payments"
  batch_input = [{
    "value"                 = data.vault_transform_encode.encoded.encoded_value,
    "transformation"        = vault_transform_transformation.ccn-fpe-dst.name,
    "decode_transformation" = vault_transform_transformation.ccn-fpe-src.name,
  }]
}
`, path)
}
