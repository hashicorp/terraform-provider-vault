// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceIdentityGroupName(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityGroup_configName(group),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityGroup_check("data.vault_identity_group.group_name"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "group_name", group),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "metadata.version", "1"),
				),
			},
		},
	})
}

func TestDataSourceIdentityGroupAlias(t *testing.T) {
	t.Parallel()
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityGroup_configAlias(group),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityGroup_check("data.vault_identity_group.group_alias"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "group_name", group),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "metadata.version", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "alias_name", group),
				),
			},
		},
	})
}

func testDataSourceIdentityGroup_check(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		resp, err := identityGroupLookup(client, map[string]interface{}{"id": rs.Primary.ID})
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
				StateAttr:    "group_id",
				VaultAttr:    "id",
			},
			{
				ResourceName: resourceName,
				StateAttr:    "group_name",
				VaultAttr:    "name",
			},
		}

		return testutil.AssertVaultStateFromResp(resp, s, group.LookupPath, tAttrs...)
	}
}

func testDataSourceIdentityGroup_configName(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

data "vault_identity_group" "group_name" {
  group_name = vault_identity_group.group.name
}
`, groupName)
}

func testDataSourceIdentityGroup_configAlias(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

resource "vault_auth_backend" "github" {
  type = "github"
  path = "github-%s"
}

resource "vault_identity_group_alias" "group_alias" {
  name = "%s"
  mount_accessor = vault_auth_backend.github.accessor
  canonical_id = vault_identity_group.group.id
}

data "vault_identity_group" "group_alias" {
  alias_name = vault_identity_group_alias.group_alias.name
  alias_mount_accessor = vault_identity_group_alias.group_alias.mount_accessor
}
`, groupName, groupName, groupName)
}
