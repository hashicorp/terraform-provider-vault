// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceIdentityEntityName(t *testing.T) {
	t.Parallel()
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "data.vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityEntity_configName(entity),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityEntity_check(resourceName),
					resource.TestCheckResourceAttr(resourceName, "entity_name", entity),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
				),
			},
		},
	})
}

func TestDataSourceIdentityEntityAlias(t *testing.T) {
	t.Parallel()
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "data.vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityEntity_configAlias(entity),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityEntity_check(resourceName),
					resource.TestCheckResourceAttr(resourceName, "entity_name", entity),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
					resource.TestCheckResourceAttr(resourceName, "aliases.#", "1"),
				),
			},
		},
	})
}

func testDataSourceIdentityEntity_check(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		resp, err := identityEntityLookup(client, map[string]interface{}{"id": rs.Primary.ID})
		if err != nil {
			return err
		}

		tAttrs := []*testutil.VaultStateTest{
			{
				ResourceName: resourceName,
				StateAttr:    "id",
				VaultAttr:    "id",
			},
			{
				ResourceName: resourceName,
				StateAttr:    "entity_id",
				VaultAttr:    "id",
			},
			{
				ResourceName: resourceName,
				StateAttr:    "entity_name",
				VaultAttr:    "name",
			},
		}

		return testutil.AssertVaultStateFromResp(resp, s, entity.LookupPath, tAttrs...)
	}
}

func testDataSourceIdentityEntity_configName(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

data "vault_identity_entity" "entity" {
  entity_name = vault_identity_entity.entity.name
}
`, entityName)
}

func testDataSourceIdentityEntity_configAlias(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

resource "vault_auth_backend" "github" {
  type = "github"
  path = "github-%s"
}

resource "vault_identity_entity_alias" "entity_alias" {
  name = "%s"
  mount_accessor = vault_auth_backend.github.accessor
  canonical_id = vault_identity_entity.entity.id
}

data "vault_identity_entity" "entity" {
  alias_name = vault_identity_entity_alias.entity_alias.name
  alias_mount_accessor = vault_identity_entity_alias.entity_alias.mount_accessor
}
`, entityName, entityName, entityName)
}
