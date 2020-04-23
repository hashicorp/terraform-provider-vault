package role

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/provider"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

var testProvider = func() *provider.Provider {
	p := provider.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_role_name", NameResource())
	return p
}()

func TestRoleNameBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-transform-role-name")
	name := acctest.RandomWithPrefix("tf-test-transform-role")

	resource.Test(t, resource.TestCase{
		//PreCheck:     func() { testUtil.TestAccPreCheck(t) },
		Providers:    map[string]terraform.ResourceProvider{
			"vault": testProvider.ResourceProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, name, "ccn-fpe"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "name", name),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations", "ccn-fpe"),
				),
			},
			{
				Config: basicConfig(path, name, "ccn-fpe+updated"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "name", name),
					resource.TestCheckResourceAttr("vault_transform_role_name.test", "transformations", "ccn-fpe+updated"),
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
	client := testProvider.SchemaProvider().Meta().(*api.Client)

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

func basicConfig(path, name, tranformations string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_role_name" "transform_role_name" {
  path = vault_mount.mount_transform.path
  name = "%s"
  transformations = ["%s"]
}
`, path, name, tranformations)
}
