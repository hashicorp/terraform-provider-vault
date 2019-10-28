package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityEntityAlias(t *testing.T) {
	entity := acctest.RandomWithPrefix("my-entity")

	nameEntity := "vault_identity_entity.entity"
	nameEntityAlias := "vault_identity_entity_alias.entity-alias"
	nameGithubA := "vault_auth_backend.githubA"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasConfig(entity, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(nameEntityAlias, "name", entity),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntity, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "mount_accessor", nameGithubA, "accessor"),
				),
			},
			{
				Config:      testAccIdentityEntityAliasConfig(entity, true),
				ExpectError: regexp.MustCompile(`IdentityEntityAlias.*already exists.*may be imported`),
			},
		},
	})
}

func testAccCheckIdentityEntityAliasDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_entity_alias" {
			continue
		}
		secret, err := client.Logical().Read(identityEntityAliasIDPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity entity %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity entity role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityEntityAliasConfig(entityName string, dupeAlias bool) string {
	ret := fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
}

resource "vault_auth_backend" "githubA" {
  type = "github"
  path = "githubA-%s"
}

resource "vault_auth_backend" "githubB" {
  type = "github"
  path = "githubB-%s"
}

resource "vault_identity_entity_alias" "entity-alias" {
  name = "%s"
  mount_accessor = "${vault_auth_backend.githubA.accessor}"
  canonical_id = "${vault_identity_entity.entity.id}"
}
`, entityName, entityName, entityName, entityName)

	// This duplicate alias tests the provider's handling of aliases that already exist but aren't
	// known to the provider.
	if dupeAlias {
		ret += fmt.Sprintf(`
resource "vault_identity_entity_alias" "entity-alias-dupe" {
  name = "%s"
  mount_accessor = "${vault_auth_backend.githubA.accessor}"
  canonical_id = "${vault_identity_entity.entity.id}"
}
`, entityName)
	}

	return ret
}
