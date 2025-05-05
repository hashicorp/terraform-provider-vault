// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityEntityAlias(t *testing.T) {
	entity := acctest.RandomWithPrefix("my-entity")

	nameEntity := "vault_identity_entity.entityA"
	nameEntityAlias := "vault_identity_entity_alias.entity-alias"
	nameGithubA := "vault_auth_backend.githubA"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntity, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntity, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, consts.FieldMountAccessor, nameGithubA, "accessor"),
				),
			},
			{
				ResourceName:      nameEntityAlias,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config:      testAccIdentityEntityAliasConfig(entity, true, false),
				ExpectError: regexp.MustCompile(`entity alias .+ already exists`),
			},
		},
	})
}

func TestAccIdentityEntityAliasDuplicateFlow(t *testing.T) {
	namePrefix := acctest.RandomWithPrefix("test-duplicate-flow")
	alias := acctest.RandomWithPrefix("alias")

	configTmpl := fmt.Sprintf(`
variable name_prefix {
  default = "%s"
}

variable entity_alias_name_1 {
  default = "%%s"
}
variable entity_alias_name_2 {
  default = "%%s"
}

resource "vault_auth_backend" "test" {
    path = "cert/${var.name_prefix}"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = var.name_prefix
    backend       = vault_auth_backend.test.path
    certificate   = <<EOT
%s
EOT
}

resource "vault_policy" "test" {
  name = "${var.name_prefix}-policy"

  policy = <<EOT
path "secret/my_app" {
  capabilities = ["update"]
}
EOT
}

resource "vault_identity_entity" "test1" {
  name = "${var.name_prefix}-1"
  policies = [
    "default",
    vault_policy.test.name,
  ]
}

resource "vault_identity_entity" "test2" {
  name = "${var.name_prefix}-2"
  policies = [
    "default",
    vault_policy.test.name,
  ]
}

resource "vault_identity_entity_alias" "test1" {
    name            = var.entity_alias_name_1
    mount_accessor  = vault_auth_backend.test.accessor
    canonical_id    = vault_identity_entity.test1.id
}

resource "vault_identity_entity_alias" "test2" {
    name            = var.entity_alias_name_2
    mount_accessor  = vault_auth_backend.test.accessor
    canonical_id    = vault_identity_entity.test2.id
}
`, namePrefix, testPKICARoot)

	aliasResource1 := "vault_identity_entity_alias.test1"
	aliasResource2 := "vault_identity_entity_alias.test2"
	entityResource1 := "vault_identity_entity.test1"
	entityResource2 := "vault_identity_entity.test2"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				// test the case where the apply operation would produce two new aliases having the same name
				// this should result in one alias being created but not the other.
				Config:      fmt.Sprintf(configTmpl, alias, alias),
				ExpectError: regexp.MustCompile(`entity alias .+ already exists`),
			},
			{
				// attempt to recover from alias name duplication failure above
				// this should result in a clean recovery from the failure above.
				Config: fmt.Sprintf(configTmpl, alias+"-1", alias+"-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						aliasResource1, consts.FieldMountAccessor,
						aliasResource2, consts.FieldMountAccessor),
					resource.TestCheckResourceAttr(
						aliasResource1, "name", alias+"-1"),
					resource.TestCheckResourceAttr(
						aliasResource2, "name", alias+"-2"),
					resource.TestCheckResourceAttrPair(
						aliasResource1, "canonical_id",
						entityResource1, "id"),
					resource.TestCheckResourceAttrPair(
						aliasResource2, "canonical_id",
						entityResource2, "id"),
				),
			},
			{
				ResourceName:      aliasResource1,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      aliasResource2,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// attempt to get back to the desired alias configuration
				Config: fmt.Sprintf(configTmpl, alias, alias+"-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						aliasResource1, consts.FieldMountAccessor,
						aliasResource2, consts.FieldMountAccessor),
					resource.TestCheckResourceAttr(
						aliasResource1, "name", alias),
					resource.TestCheckResourceAttr(
						aliasResource2, "name", alias+"-2"),
				),
			},
			{
				ResourceName:      aliasResource1,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      aliasResource2,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// delete one of the alias's to ensure an update operation re-creates it.
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					aliases, err := entity.FindAliases(client, &entity.FindAliasParams{
						Name: alias,
					})
					if err != nil {
						t.Fatal(err)
					}

					if len(aliases) != 1 {
						t.Fatalf("expected Alias %q not found in Vault", alias)
					}

					_, err = client.Logical().Delete(entity.JoinAliasID(aliases[0].ID))
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: fmt.Sprintf(configTmpl, alias, alias+"-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						aliasResource1, consts.FieldMountAccessor,
						aliasResource2, consts.FieldMountAccessor),
					resource.TestCheckResourceAttr(
						aliasResource1, "name", alias),
					resource.TestCheckResourceAttr(
						aliasResource2, "name", alias+"-2"),
				),
			},
			{
				// duplicate during an update operation
				// this should result Vault catching the duplicate and returning an error.
				Config:      fmt.Sprintf(configTmpl, alias, alias),
				ExpectError: regexp.MustCompile(`alias with combination of mount accessor and name already exists`),
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityA, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityA, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, consts.FieldMountAccessor, nameGithubA, "accessor"),
				),
			},
			{
				Config: testAccIdentityEntityAliasConfig(entity, false, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityB, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityB, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, consts.FieldMountAccessor, nameGithubB, "accessor"),
				),
			},
		},
	})
}

func testAccCheckIdentityEntityAliasDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_entity_alias" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(entity.JoinAliasID(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity entity %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity entity role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccIdentityEntityAlias_Metadata(t *testing.T) {
	entity := acctest.RandomWithPrefix("my-entity")

	nameEntityA := "vault_identity_entity.entityA"
	nameEntityB := "vault_identity_entity.entityB"
	nameEntityAlias := "vault_identity_entity_alias.entity-alias"
	nameGithubA := "vault_auth_backend.githubA"
	nameGithubB := "vault_auth_backend.githubB"

	// TODO add back empty custom_metadata update tests
	// once bug in Vault is resolved
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityEntityAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityAliasMetadataConfig(entity, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityA, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityA, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, consts.FieldMountAccessor, nameGithubA, "accessor"),
					resource.TestCheckResourceAttr(nameEntityAlias, "custom_metadata.%", "1"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "custom_metadata.version", nameEntityA, "metadata.version"),
				),
			},
			{
				Config: testAccIdentityEntityAliasMetadataConfig(entity, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(nameEntityAlias, "name", nameEntityB, "name"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "canonical_id", nameEntityB, "id"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, consts.FieldMountAccessor, nameGithubB, "accessor"),
					resource.TestCheckResourceAttr(nameEntityAlias, "custom_metadata.%", "1"),
					resource.TestCheckResourceAttrPair(nameEntityAlias, "custom_metadata.version", nameEntityB, "metadata.version"),
				),
			},
		},
	})
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

func testAccIdentityEntityAliasMetadataConfig(entityPrefix string, entitySuffix bool) string {
	entityId := "A"
	if entitySuffix {
		entityId = "B"
	}

	result := fmt.Sprintf(`
	resource "vault_identity_entity" "entityA" {
		name = "%s-A"
		policies = ["test"]
		metadata = {
			version = "1"
		  }
	  }

	  resource "vault_identity_entity" "entityB" {
		name = "%s-B"
		policies = ["test"]
		metadata = {
			version = "2"
		  }
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
		custom_metadata = vault_identity_entity.entity%s.metadata
	  }

`, entityPrefix, entityPrefix, entityPrefix, entityPrefix, entityId, entityId, entityId, entityId)

	return result
}
