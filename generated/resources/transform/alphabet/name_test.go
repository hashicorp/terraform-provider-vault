package alphabet

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	sdk_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_alphabet_name", NameResource())
	return p
}()

func TestAlphabetName(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": nameTestProvider.SchemaProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "numerics", "0123456789"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "name", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "alphabet", "0123456789"),
				),
			},
			{
				Config: basicConfig(path, "numerics", "012345678"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "name", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_alphabet_name.test", "alphabet", "012345678"),
				),
			},
			{
				ResourceName:      "vault_transform_alphabet_name.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func destroy(s *terraform.State) error {
	client := nameTestProvider.SchemaProvider().Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_alphabet_name" {
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

func basicConfig(path, name, alphabet string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_alphabet_name" "test" {
  path = vault_mount.mount_transform.path
  name = "%s"
  alphabet = "%s"
}
`, path, name, alphabet)
}
