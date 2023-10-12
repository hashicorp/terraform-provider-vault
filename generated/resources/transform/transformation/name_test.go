// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transformation

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	sdk_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

var nameTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_mount", vault.UpdateSchemaResource(vault.MountResource()))
	p.RegisterResource("vault_transform_transformation_name", vault.UpdateSchemaResource(NameResource()))
	return p
}()

func TestTransformationName(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")

	resourceName := "vault_transform_transformation_name.test"
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestEntPreCheck(t) },
		Providers: map[string]*sdk_schema.Provider{
			"vault": nameTestProvider.SchemaProvider(),
		},
		CheckDestroy: destroy,
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "ccn-fpe", "fpe", "ccn", "internal", "payments", "*"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "name", "ccn-fpe"),
					resource.TestCheckResourceAttr(resourceName, "type", "fpe"),
					resource.TestCheckResourceAttr(resourceName, "template", "ccn"),
					resource.TestCheckResourceAttr(resourceName, "tweak_source", "internal"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.0", "payments"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "masking_character", "*"),
				),
			},
			{
				ResourceName: resourceName,
				ImportState:  true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 state but received %+v", states)
					}
					state := states[0]
					if state.Attributes["%"] != "11" {
						t.Fatalf("expected 11 attributes but received %s", state.Attributes["%"])
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
					var expectDeletionAllowed string
					if provider.IsAPISupported(nameTestProvider.SchemaProvider().Meta(), provider.VaultVersion112) {
						expectDeletionAllowed = "true"
					}
					if state.Attributes["deletion_allowed"] != expectDeletionAllowed {
						t.Fatalf("expected %q, received %q", expectDeletionAllowed, state.Attributes["deletion_allowed"])
					}
					return nil
				},
			},
			{
				Config: basicConfig(path, "ccn-fpe", "fpe", "ccn-1", "generated", "payments-1", "-"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "name", "ccn-fpe"),
					resource.TestCheckResourceAttr(resourceName, "type", "fpe"),
					resource.TestCheckResourceAttr(resourceName, "template", "ccn-1"),
					resource.TestCheckResourceAttr(resourceName, "tweak_source", "generated"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.0", "payments-1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "masking_character", "-"),
				),
			},
			{
				Config:   basicConfig(path, "ccn-fpe", "fpe", "ccn-1", "generated", "payments-1", "-"),
				PlanOnly: true,
			},
		},
	})
}

func destroy(s *terraform.State) error {
	client := nameTestProvider.SchemaProvider().Meta().(*provider.ProviderMeta).GetClient()

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
  path              = vault_mount.mount_transform.path
  name              = "%s"
  type              = "%s"
  template          = "%s"
  tweak_source      = "%s"
  allowed_roles     = ["%s"]
  masking_character = "%s"
  deletion_allowed  = true
}
`, path, name, tp, template, tweakSource, allowedRoles, maskingChar)
}
