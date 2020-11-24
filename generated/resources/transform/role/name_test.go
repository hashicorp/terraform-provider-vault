package role

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/vault"
	"github.com/hashicorp/vault/api"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_role_name", NameResource())
	return p
}()

func TestRoleName(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestEntPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": nameTestProvider.ResourceProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, role, "ccn-fpe"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "name", role),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations.0", "ccn-fpe"),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations.#", "1"),
				),
			},
			{
				Config: basicConfig(path, role, "ccn-fpe+updated"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "name", role),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations.0", "ccn-fpe+updated"),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations.#", "1"),
				),
			},
			{
				ResourceName:      "vault_transform_role_name.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func destroy(s *terraform.State) error {
	client := nameTestProvider.SchemaProvider().Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_role_name" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func basicConfig(path, role, tranformations string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_role_name" "test" {
  path = vault_mount.mount_transform.path
  name = "%s"
  transformations = ["%s"]
}
`, path, role, tranformations)
}
