package alphabet

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/schema"
	"github.com/terraform-providers/terraform-provider-vault/util"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.MountResource())
	p.RegisterResource("vault_transform_alphabet_name", NameResource())
	return p
}()

func TestAlphabetName(t *testing.T) {
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
