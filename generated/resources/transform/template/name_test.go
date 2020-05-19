package template

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/generated/resources/transform/alphabet"
	"github.com/terraform-providers/terraform-provider-vault/schema"
	"github.com/terraform-providers/terraform-provider-vault/util"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_alphabet_name", alphabet.NameResource())
	p.RegisterResource("vault_transform_template_name", NameResource())
	return p
}()

func TestTemplateName(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": nameTestProvider.ResourceProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "regex", `(\\d{4})-(\\d{4})-(\\d{4})-(\\d{4})`, "numerics"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "pattern", `(\d{4})-(\d{4})-(\d{4})-(\d{4})`),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "alphabet", "numerics"),
				),
			},
			{
				Config: basicConfig(path, "regex", `(\\d{9})`, "builtin/numeric"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "name", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "type", "regex"),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "pattern", `(\d{9})`),
					resource.TestCheckResourceAttr("vault_transform_template_name.test", "alphabet", "builtin/numeric"),
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
	client := nameTestProvider.SchemaProvider().Meta().(*api.Client)

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

func basicConfig(path, tp, pattern, alphabet string) string {
	return fmt.Sprintf(`
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
  type = "%s"
  pattern = "%s"
  alphabet = "%s"
}
`, path, tp, pattern, alphabet)
}
