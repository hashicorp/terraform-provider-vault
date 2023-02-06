// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccIdentityGroupPoliciesExclusive(t *testing.T) {
	resourceName := "vault_identity_group_policies.policies"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupPoliciesDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupPoliciesConfigExclusive(),
				Check:  testAccIdentityGroupPoliciesCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityGroupPoliciesConfigExclusiveUpdate(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "policies.1", "test"),
					testAccIdentityGroupPoliciesCheckAttrs(resourceName),
				),
			},
		},
	})
}

func TestAccIdentityGroupPoliciesNonExclusive(t *testing.T) {
	resourceNameDev := "vault_identity_group_policies.dev"
	resourceNameTest := "vault_identity_group_policies.test"
	resourceNameGroup := "vault_identity_group.group"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupPoliciesDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupPoliciesConfigNonExclusive(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceNameDev, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceNameTest, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceNameTest, "policies.0", "test"),
					testAccIdentityGroupCheckAttrs(resourceNameGroup),
					testAccIdentityGroupPoliciesCheckAttrs(resourceNameDev),
					testAccIdentityGroupPoliciesCheckAttrs(resourceNameTest),
				),
			},
			{
				Config: testAccIdentityGroupPoliciesConfigNonExclusiveUpdate(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameDev, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceNameDev, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceNameTest, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceNameTest, "policies.0", "foo"),
					testAccIdentityGroupCheckAttrs(resourceNameGroup),
					testAccIdentityGroupPoliciesCheckAttrs(resourceNameDev),
					testAccIdentityGroupPoliciesCheckAttrs(resourceNameTest),
				),
			},
		},
	})
}

func testAccCheckidentityGroupPoliciesDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group_policies" {
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

		apiPolicies, err := readIdentityGroupPolicies(client, rs.Primary.ID, false)
		if err != nil {
			return err
		}
		length := rs.Primary.Attributes["policies.#"]

		if length != "" {
			count, err := strconv.Atoi(length)
			if err != nil {
				return fmt.Errorf("expected %s.# to be a number, got %q", "policies.#", length)
			}

			for i := 0; i < count; i++ {
				resourcePolicy := rs.Primary.Attributes["policies."+strconv.Itoa(i)]
				if found, _ := util.SliceHasElement(apiPolicies, resourcePolicy); found {
					return fmt.Errorf("identity group %s still has policy %s", rs.Primary.ID, resourcePolicy)
				}
			}
		}
	}
	return nil
}

func testAccIdentityGroupPoliciesCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		v, err := strconv.ParseBool(rs.Primary.Attributes["exclusive"])
		if err != nil {
			return err
		}

		isSubset := !v

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := group.IdentityGroupIDPath(rs.Primary.ID)

		attrs := map[string]string{
			"group_id":   "id",
			"group_name": "name",
			"policies":   "policies",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}
			if k == "policies" {
				ta.IsSubset = isSubset
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityGroupPoliciesConfigExclusive() string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  external_policies = true
}

resource "vault_identity_group_policies" "policies" {
  group_id = vault_identity_group.group.id
  policies = ["test"]
}`)
}

func testAccIdentityGroupPoliciesConfigExclusiveUpdate() string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  external_policies = true
}

resource "vault_identity_group_policies" "policies" {
  group_id = vault_identity_group.group.id
  policies = ["dev", "test"]
}`)
}

func testAccIdentityGroupPoliciesConfigNonExclusive() string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  external_policies = true
}

resource "vault_identity_group_policies" "dev" {
	group_id = vault_identity_group.group.id
  exclusive = false
  policies = ["dev"]
}


resource "vault_identity_group_policies" "test" {
  group_id = vault_identity_group.group.id
  exclusive = false
  policies = ["test"]
}
`)
}

func testAccIdentityGroupPoliciesConfigNonExclusiveUpdate() string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  external_policies = true
}

resource "vault_identity_group_policies" "dev" {
	group_id = vault_identity_group.group.id
  exclusive = false
  policies = ["dev"]
}


resource "vault_identity_group_policies" "test" {
  group_id = vault_identity_group.group.id
  exclusive = false
  policies = ["foo"]
}
`)
}
