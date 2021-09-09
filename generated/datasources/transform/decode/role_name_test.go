package decode

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	sdk_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/role"
	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/transformation"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

var roleNameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_transformation_name", transformation.NameResource())
	p.RegisterResource("vault_transform_role_name", role.NameResource())
	p.RegisterDataSource("vault_transform_decode_role_name", RoleNameDataSource())
	return p
}()

func TestDecodeBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": roleNameTestProvider.SchemaProvider(),
		},
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_transform_decode_role_name.test", "decoded_value"),
				),
			},
		},
	})
}

func basicConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_transformation_name" "ccn-fpe" {
  path = vault_mount.transform.path
  name = "ccn-fpe"
  type = "fpe"
  template = "builtin/creditcardnumber"
  tweak_source = "internal"
  allowed_roles = ["payments"]
}
resource "vault_transform_role_name" "payments" {
  path = vault_transform_transformation_name.ccn-fpe.path
  name = "payments"
  transformations = ["ccn-fpe"]
}
data "vault_transform_decode_role_name" "test" {
    path      = vault_transform_role_name.payments.path
    role_name = "payments"
    value     = "9300-3376-4943-8903"
}
`, path)
}

func TestDecodeBatch(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": roleNameTestProvider.SchemaProvider(),
		},
		Steps: []resource.TestStep{
			{
				Config: batchConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transform_decode_role_name.test", "batch_results.#", "1"),
					resource.TestCheckResourceAttrSet("data.vault_transform_decode_role_name.test", "batch_results.0.decoded_value"),
				),
			},
		},
	})
}

func batchConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_transformation_name" "ccn-fpe" {
  path = vault_mount.transform.path
  name = "ccn-fpe"
  type = "fpe"
  template = "builtin/creditcardnumber"
  tweak_source = "internal"
  allowed_roles = ["payments"]
}
resource "vault_transform_role_name" "payments" {
  path = vault_transform_transformation_name.ccn-fpe.path
  name = "payments"
  transformations = ["ccn-fpe"]
}
data "vault_transform_decode_role_name" "test" {
    path      = vault_transform_role_name.payments.path
    role_name = "payments"
    batch_input = [{"value":"9300-3376-4943-8903"}]
}
`, path)
}
