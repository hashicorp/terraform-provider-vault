// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityGroupMemberGroupIdsNonExclusive(t *testing.T) {
	group1 := acctest.RandomWithPrefix("group")
	var tester1 group.GroupMemberTester

	group2 := acctest.RandomWithPrefix("group")
	var tester2 group.GroupMemberTester

	group3 := acctest.RandomWithPrefix("group")
	var tester3 group.GroupMemberTester

	resourceNameDev := "vault_identity_group_member_group_ids.dev"
	resourceNameTest := "vault_identity_group_member_group_ids.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberGroupIdsConfigNonExclusive(group1, group2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_group_ids.#", "1"),
					tester1.SetMemberGroups(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_group_ids.#", "1"),
					tester2.SetMemberGroups(resourceNameTest),
				),
			},
			{
				Config: testAccIdentityGroupMemberGroupIdsConfigNonExclusiveUpdate(group1, group3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_group_ids.#", "1"),
					tester1.CheckMemberGroups(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_group_ids.#", "1"),
					tester2.SetMemberGroups(resourceNameTest),
					tester3.SetMemberGroups(resourceNameTest),
				),
			},
			{
				Config: testAccIdentityGroupMemberGroupIdsConfigNonExclusiveUpdate(group1, group3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_group_ids.#", "1"),
					tester1.CheckMemberGroups(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_group_ids.#", "1"),
					tester2.CheckMemberGroups(resourceNameTest),
					tester3.CheckMemberGroups(resourceNameTest),
				),
			},
		},
	})
}

func testAccIdentityGroupMemberGroupIdsConfigNonExclusive(devGroupName, testGroupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
    external_member_group_ids = true
}

resource "vault_identity_group" "dev_group" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group" "test_group" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_group_ids" "dev" {
	group_id = vault_identity_group.group.id
  	exclusive = false
  	member_group_ids = [vault_identity_group.dev_group.id]
}


resource "vault_identity_group_member_group_ids" "test" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_group_ids = [vault_identity_group.test_group.id]
}
`, devGroupName, testGroupName)
}

func testAccIdentityGroupMemberGroupIdsConfigNonExclusiveUpdate(devGroupName, fooGroupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_group_ids = true
}

resource "vault_identity_group" "dev_group" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group" "foo_group" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_group_ids" "dev" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_group_ids = [vault_identity_group.dev_group.id]
}

resource "vault_identity_group_member_group_ids" "test" {
  	group_id = vault_identity_group.group.id
	exclusive = false
	member_group_ids = [vault_identity_group.foo_group.id]
}
`, devGroupName, fooGroupName)
}
