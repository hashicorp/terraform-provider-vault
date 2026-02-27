// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccIdentityGroupMemberEntityIdsExclusiveEmpty(t *testing.T) {
	devEntity := acctest.RandomWithPrefix("dev-entity")

	resourceName := "vault_identity_group_member_entity_ids.member_entity_ids"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty(),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty(),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName),
				),
			},
		},
	})
}

func TestAccIdentityGroupMemberEntityIdsExclusive(t *testing.T) {
	devEntity := acctest.RandomWithPrefix("dev-entity")
	testEntity := acctest.RandomWithPrefix("test-entity")
	resourceName := "vault_identity_group_member_entity_ids.member_entity_ids"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "member_entity_ids.#", "1"),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveUpdate(devEntity, testEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "member_entity_ids.#", "2"),
				),
			},
		},
	})
}

func TestAccIdentityGroupMemberEntityIdsNonExclusiveEmpty(t *testing.T) {
	devEntity := acctest.RandomWithPrefix("dev-entity")
	testEntity := acctest.RandomWithPrefix("test-entity")
	var devEntityTester group.GroupMemberTester
	resourceNameDev := "vault_identity_group_member_entity_ids.dev"
	resourceNameTest := "vault_identity_group_member_entity_ids.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameDev),
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameTest),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					devEntityTester.SetMemberEntities(resourceNameDev),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusive(devEntity, testEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameDev),
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameTest),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					devEntityTester.CheckMemberEntities(resourceNameDev),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameDev),
					testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceNameTest),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					devEntityTester.CheckMemberEntities(resourceNameDev),
				),
			},
		},
	})
}

type identityGMETest struct {
	name        string
	exclusive   bool
	entityCount int
}

func TestAccIdentityGroupMemberEntityIdsNonExclusive(t *testing.T) {
	var tester1 group.GroupMemberTester
	entity1 := acctest.RandomWithPrefix("entity")

	entity2 := acctest.RandomWithPrefix("entity")
	var tester2 group.GroupMemberTester

	entity3 := acctest.RandomWithPrefix("entity")
	var tester3 group.GroupMemberTester

	resourceNameDev := "vault_identity_group_member_entity_ids.dev"
	resourceNameTest := "vault_identity_group_member_entity_ids.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusive(entity1, entity2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					tester1.SetMemberEntities(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "1"),
					tester2.SetMemberEntities(resourceNameTest),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(entity1, entity3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					tester1.CheckMemberEntities(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "1"),
					tester2.SetMemberEntities(resourceNameTest),
					tester3.SetMemberEntities(resourceNameTest),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(entity1, entity3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "member_entity_ids.#", "1"),
					tester1.CheckMemberEntities(resourceNameDev),
					resource.TestCheckResourceAttr(resourceNameTest, "member_entity_ids.#", "1"),
					tester2.CheckMemberEntities(resourceNameTest),
					tester3.CheckMemberEntities(resourceNameTest),
				),
			},
		},
	})
}

func TestAccIdentityGroupMemberEntityIdsDynamic(t *testing.T) {
	tests := []*identityGMETest{
		{
			name:        acctest.RandomWithPrefix("entity"),
			exclusive:   false,
			entityCount: 0,
		},
		{
			name:        acctest.RandomWithPrefix("entity"),
			exclusive:   false,
			entityCount: 1,
		},
		{
			name:        acctest.RandomWithPrefix("entity"),
			exclusive:   false,
			entityCount: 2,
		},
		{
			name:        acctest.RandomWithPrefix("entity"),
			exclusive:   false,
			entityCount: 3,
		},
		{
			name:        acctest.RandomWithPrefix("entity"),
			exclusive:   false,
			entityCount: 4,
		},
	}

	groupName := acctest.RandomWithPrefix("group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGMEIDynamic(groupName, true, tests...),
				Check:  testIdentityGMEIMembers(groupName, tests...),
			},
			{
				// increment entities
				PreConfig: func() {
					for _, t := range tests {
						t.entityCount++
					}
				},
				Config: testAccIdentityGMEIDynamic(groupName, true, tests...),
				Check:  testIdentityGMEIMembers(groupName, tests...),
			},
			{
				// decrement entities
				PreConfig: func() {
					for _, t := range tests {
						t.entityCount--
					}
				},
				Config: testAccIdentityGMEIDynamic(groupName, true, tests...),
				Check:  testIdentityGMEIMembers(groupName, tests...),
			},
			{
				// decrement tests, simulates resource destruction
				Config: testAccIdentityGMEIDynamic(groupName, true, tests[:len(tests)-1]...),
				Check:  testIdentityGMEIMembers(groupName, tests[:len(tests)-1]...),
			},
			{
				// alternate group_name to ensure that `vault_identity_group` doesn't wipe out our identities
				Config: testAccIdentityGMEIDynamic(groupName+"-new", true, tests...),
				Check:  testIdentityGMEIMembers(groupName+"-new", tests...),
			},
		},
	})
}

func testIdentityGMEIMembers(groupName string, tests ...*identityGMETest) resource.TestCheckFunc {
	var funcs []resource.TestCheckFunc
	for _, t := range tests {
		r := fmt.Sprintf("vault_identity_group_member_entity_ids.%s", t.name)
		funcs = append(funcs,
			resource.TestCheckResourceAttr(r, "member_entity_ids.#", strconv.Itoa(t.entityCount)),
			resource.TestCheckResourceAttr(r, "exclusive", fmt.Sprintf("%t", t.exclusive)),
			testAccIdentityGroupMemberEntityIdsCheckAttrs(r),
		)
	}
	return resource.ComposeTestCheckFunc(funcs...)
}

func testAccIdentityGMEIDynamic(groupName string, externalGroup bool, tests ...*identityGMETest) string {
	fragments := []string{
		fmt.Sprintf(`
resource "vault_identity_group" "group" {
		external_member_entity_ids = %t
		name                       = "%s"
	}
`, externalGroup, groupName),
	}

	for i, t := range tests {
		fragments = append(
			fragments, fmt.Sprintf(
				`
resource "vault_identity_entity" "entity_%d"{
  count = %d
  name  = "%s_${count.index}"
  metadata = {
    version = "2"
  }
}

resource "vault_identity_group_member_entity_ids" "%s" {
  group_id          = vault_identity_group.group.id
  exclusive         = %t
  member_entity_ids = coalesce(vault_identity_entity.entity_%d.*.id)
}
	`, i, t.entityCount, t.name, t.name, t.exclusive, i),
		)
	}

	config := strings.Join(fragments, "\n")

	return config
}

func testAccCheckidentityGroupMemberEntityIdsDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group_member_entity_ids" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		if _, err := group.ReadIdentityGroup(client, rs.Primary.ID, false); err != nil {
			if group.IsIdentityNotFoundError(err) {
				continue
			}
			return err
		}

		apiMemberEntityIds, err := readIdentityGroupMemberEntityIds(client, rs.Primary.ID, false)
		if err != nil {
			return err
		}
		length := rs.Primary.Attributes["member_entity_ids.#"]

		if length != "" {
			count, err := strconv.Atoi(length)
			if err != nil {
				return fmt.Errorf("expected %s.# to be a number, got %q", "member_entity_ids.#", length)
			}

			for i := 0; i < count; i++ {
				resourcePolicy := rs.Primary.Attributes["member_entity_ids."+strconv.Itoa(i)]
				if found, _ := util.SliceHasElement(apiMemberEntityIds, resourcePolicy); found {
					return fmt.Errorf("identity group %s still has member entity id %s", rs.Primary.ID, resourcePolicy)
				}
			}
		}
	}
	return nil
}

func testAccIdentityGroupMemberEntityIdsCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		var isSubset bool
		if rs.Type == "vault_identity_group_member_entity_ids" {
			v, err := strconv.ParseBool(rs.Primary.Attributes["exclusive"])
			if err != nil {
				return err
			}

			isSubset = !v
		}

		id := rs.Primary.ID
		path := group.IdentityGroupIDPath(id)
		tAttrs := []*testutil.VaultStateTest{
			{
				ResourceName: resourceName,
				StateAttr:    "group_id",
				VaultAttr:    "id",
			},
			{
				ResourceName: resourceName,
				StateAttr:    "member_entity_ids",
				VaultAttr:    "member_entity_ids",
				IsSubset:     isSubset,
			},
		}
		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty() string {
	return `
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
  	group_id = vault_identity_group.group.id
}`
}

func testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
  group_id = vault_identity_group.group.id
  member_entity_ids = [vault_identity_entity.dev.id]
}`, devEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigExclusiveUpdate(devEntityName, testEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "test" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
	group_id = vault_identity_group.group.id
	member_entity_ids = [vault_identity_entity.dev.id, vault_identity_entity.test.id]
}`, devEntityName, testEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
  	exclusive = false
  	member_entity_ids = [vault_identity_entity.dev_entity.id]
}


resource "vault_identity_group_member_entity_ids" "test" {
	group_id = vault_identity_group.group.id
	exclusive = false
}
`, devEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusive(devEntityName, testEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "test_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
  	exclusive = false
  	member_entity_ids = [vault_identity_entity.dev_entity.id]
}


resource "vault_identity_group_member_entity_ids" "test" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.test_entity.id]
}
`, devEntityName, testEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(devEntityName, fooEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "foo_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.dev_entity.id]
}

resource "vault_identity_group_member_entity_ids" "test" {
  	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.foo_entity.id]
}
`, devEntityName, fooEntityName)
}
