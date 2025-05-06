// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityGroup(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resourceName := "vault_identity_group.group"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check:  testAccIdentityGroupCheckAttrs(resourceName),
			},
		},
	})
}

func TestAccIdentityGroupUpdate(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_group.group"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "type", "external"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdate(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s-2", group)),
					resource.TestCheckResourceAttr(resourceName, "type", "internal"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "policies.1", "test"),
					resource.TestCheckResourceAttr(resourceName, "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "member_group_ids.#", "0"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdateRemovePolicies(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "type", "internal"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdateMembers(group, entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "type", "internal"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "policies.1", "test"),
					resource.TestCheckResourceAttr(resourceName, "member_entity_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "member_group_ids.#", "1"),
				),
			},
			{
				Config: testAccIdentityGroupConfigExternalMembers(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "type", "external"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "member_group_ids.#", "0"),
				),
			},
		},
	})
}

func TestAccIdentityGroupExternal(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resourceName := "vault_identity_group.group"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check:  testAccIdentityGroupCheckAttrs(resourceName),
			},
		},
	})
}

func TestAccIdentityGroup_DuplicateCreate(t *testing.T) {
	// group identity names are stored in lower case,
	// this test attempts to create two resources with different casing for the
	// same lower case group name.
	group := fmt.Sprintf("test_group_%d", acctest.RandInt())
	config := fmt.Sprintf(`
resource "vault_identity_group" "test_lower" {
  name     = %q
  type     = "external"
  policies = ["default"]
}

resource "vault_identity_group" "test_upper" {
  name     = %q
  type     = "external"
  policies = ["default"]
}
`, group, strings.ToUpper(group[0:1])+group[1:])

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`(?i)failed to create identity group %q, reason=group already exists .+`, group)),
			},
		},
	})
}

func TestIdentityGroupExternalGroupIDsUpgradeV0(t *testing.T) {
	tests := []struct {
		name     string
		rawState map[string]interface{}
		want     map[string]interface{}
		wantErr  bool
	}{
		{
			name: "basic",
			rawState: map[string]interface{}{
				fieldExternalMemberGroupIDs: nil,
			},
			want: map[string]interface{}{
				fieldExternalMemberGroupIDs: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identityGroupExternalGroupIDsUpgradeV0(nil, tt.rawState, nil)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("identityGroupExternalGroupIDsUpgradeV0() error = %#v, wantErr %#v", err, tt.wantErr)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("identityGroupExternalGroupIDsUpgradeV0() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func testAccCheckIdentityGroupDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(group.IdentityGroupIDPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity group %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity group role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityGroupCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		extPolicies, err := strconv.ParseBool(rs.Primary.Attributes["external_policies"])
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		id := rs.Primary.ID
		path := group.IdentityGroupIDPath(id)

		attrs := map[string]string{
			"name":     "name",
			"policies": "policies",
			"type":     "type",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			// in the case of external policies it is possible that the resource_identity_group's policies are out of
			// sync with vault, in the case where the group is resource created/updated within the same terraform
			// apply operation. We can skip this test for now.
			if k == "policies" {
				if extPolicies {
					continue
				}
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityGroupConfig(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdate(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s-2"
  type = "internal"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdateRemovePolicies(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s-2"
  type = "internal"
  policies = []
  metadata = {
    version = "2"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdateMembers(groupName string, entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "internal"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }

  member_entity_ids = [vault_identity_entity.entity.id]
  member_group_ids = [vault_identity_group.other_group.id]
}

resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }
}

resource "vault_identity_group" "other_group" {
  name = "other_%s"
}
`, groupName, entityName, groupName)
}

func testAccIdentityGroupConfigExternalMembers(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }

  member_entity_ids = ["member entities can't be set for external groups"]
  member_group_ids = ["member groups can't be set for external groups"]
}`, groupName)
}
