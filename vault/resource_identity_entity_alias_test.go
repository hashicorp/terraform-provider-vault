package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityEntityAlias(t *testing.T) {
	entity := acctest.RandomWithPrefix("my-entity")

	nameEntity := "vault_identity_entity.entityA"
	nameEntityAlias := "vault_identity_entity_alias.entity-alias"
	nameGithubA := "vault_auth_backend.githubA"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntity, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntity, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "mount_accessor", nameGithubA, "accessor"),
				),
			},
			{
				Config:      testAccIdentityEntityAliasConfig(entity, true, false),
				ExpectError: regexp.MustCompile(`IdentityEntityAlias.*already exists.*may be imported`),
			},
		},
	})
}

func TestAccIdentityEntityAlias_Update(t *testing.T) {
	entity := acctest.RandomWithPrefix("my-entity")

	nameEntityA := "vault_identity_entity.entityA"
	nameEntityB := "vault_identity_entity.entityB"
	nameEntityAlias := "vault_identity_entity_alias.entity-alias"
	nameGithubA := "vault_auth_backend.githubA"
	nameGithubB := "vault_auth_backend.githubB"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityA, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityA, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "mount_accessor", nameGithubA, "accessor"),
				),
			},
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityB, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityB, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "mount_accessor", nameGithubB, "accessor"),
				),
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

func testAccIdentityEntityAliasConfig(entityName string, dupeAlias bool, altTarget bool) string {
	entityId := "A"
	if altTarget {
		entityId = "B"
	}

	ret := fmt.Sprintf(`
resource "vault_identity_entity" "entityA" {
  name = "%s-A"
  policies = ["test"]
}

resource "vault_identity_entity" "entityB" {
  name = "%s-B"
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
  name = vault_identity_entity.entity%s.name
  mount_accessor = vault_auth_backend.github%s.accessor
  canonical_id = vault_identity_entity.entity%s.id
}
`, entityName, entityName, entityName, entityName, entityId, entityId, entityId)

	// This duplicate alias tests the provider's handling of aliases that already exist but aren't
	// known to the provider.
	if dupeAlias {
		ret += fmt.Sprintf(`
resource "vault_identity_entity_alias" "entity-alias-dupe" {
  name = vault_identity_entity.entity%s.name
  mount_accessor = vault_auth_backend.githubA.accessor
  canonical_id = vault_identity_entity.entity%s.id
}
`, entityId, entityId)
	}

	return ret
}
