package transformation

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
	p.RegisterResource("vault_transform_transformation_name", NameResource())
	return p
}()

func TestTransformationName(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": nameTestProvider.SchemaProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "ccn-fpe", "fpe", "ccn", "internal", "payments", "*"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "name", "ccn-fpe"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "type", "fpe"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "template", "ccn"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "tweak_source", "internal"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "allowed_roles.0", "payments"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "masking_character", "*"),
				),
			},
			{
				ResourceName: "vault_transform_transformation_name.test",
				ImportState:  true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 state but received %+v", states)
					}
					state := states[0]
					if state.Attributes["%"] != "9" {
						t.Fatalf("expected 9 attributes but received %d", len(state.Attributes))
					}
					if state.Attributes["templates.#"] != "1" {
						t.Fatalf("expected %q, received %q", "1", state.Attributes["templates.#"])
					}
					if state.Attributes["type"] != "fpe" {
						t.Fatalf("expected %q, received %q", "fpe", state.Attributes["type"])
					}
					if state.Attributes["id"] == "" {
						t.Fatal("expected value for id, received nothing")
					}
					if state.Attributes["allowed_roles.#"] != "1" {
						t.Fatalf("expected %q, received %q", "1", state.Attributes["allowed_roles.#"])
					}
					if state.Attributes["templates.0"] != "ccn" {
						t.Fatalf("expected %q, received %q", "ccn", state.Attributes["templates.0"])
					}
					if state.Attributes["tweak_source"] != "internal" {
						t.Fatalf("expected %q, received %q", "internal", state.Attributes["tweak_source"])
					}
					if state.Attributes["path"] == "" {
						t.Fatal("expected a value for path, received nothing")
					}
					if state.Attributes["allowed_roles.0"] != "payments" {
						t.Fatalf("expected %q, received %q", "payments", state.Attributes["allowed_roles.0"])
					}
					if state.Attributes["name"] != "ccn-fpe" {
						t.Fatalf("expected %q, received %q", "ccn-fpw", state.Attributes["name"])
					}
					return nil
				},
			},
			{
				Config: basicConfig(path, "ccn-fpe", "fpe", "ccn-1", "generated", "payments-1", "-"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "name", "ccn-fpe"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "type", "fpe"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "template", "ccn-1"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "tweak_source", "generated"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "allowed_roles.0", "payments-1"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr("vault_transform_transformation_name.test", "masking_character", "-"),
				),
			},
		},
	})
}

func destroy(s *terraform.State) error {
	client := nameTestProvider.SchemaProvider().Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_transformation_name" {
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

func basicConfig(path, name, tp, template, tweakSource, allowedRoles, maskingChar string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_transformation_name" "test" {
  path = vault_mount.mount_transform.path
  name = "%s"
  type = "%s"
  template = "%s"
  tweak_source = "%s"
  allowed_roles = ["%s"]
  masking_character = "%s"
}
`, path, name, tp, template, tweakSource, allowedRoles, maskingChar)
}
