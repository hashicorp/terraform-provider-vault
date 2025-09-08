// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccIdentityEntityPoliciesExclusive(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityEntityPoliciesDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityPoliciesConfigExclusive(entity),
				Check:  testAccIdentityEntityPoliciesCheckAttrs("vault_identity_entity_policies.policies"),
			},
			{
				Config: testAccIdentityEntityPoliciesConfigExclusiveUpdate(entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityEntityPoliciesCheckAttrs("vault_identity_entity_policies.policies"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.policies", "policies.#", "2"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.policies", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.policies", "policies.1", "test"),
				),
			},
		},
	})
}

func TestAccIdentityEntityPoliciesNonExclusive(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckidentityEntityPoliciesDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityPoliciesConfigNonExclusive(entity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.0", "test"),
				),
			},
			{
				Config: testAccIdentityEntityPoliciesConfigNonExclusiveUpdate(entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityEntityPoliciesCheckLogical("vault_identity_entity.entity", []string{"dev", "foo"}),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.0", "foo"),
				),
			},
			{
				Config: testAccIdentityEntityPoliciesConfigNonExclusiveUpdateEntity(entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityEntityPoliciesCheckLogical("vault_identity_entity.entity", []string{"dev", "foo"}),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.dev", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_entity_policies.test", "policies.0", "foo"),
				),
			},
		},
	})
}

func testAccCheckidentityEntityPoliciesDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_entity_policies" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		if _, err := readIdentityEntity(client, rs.Primary.ID, false); err != nil {
			if group.IsIdentityNotFoundError(err) {
				continue
			}
			return err
		}

		apiPolicies, err := readIdentityEntityPolicies(client, rs.Primary.ID)
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
					return fmt.Errorf("identity entity %s still has policy %s", rs.Primary.ID, resourcePolicy)
				}
			}
		}
	}
	return nil
}

func testAccIdentityEntityPoliciesCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := entity.JoinEntityID(rs.Primary.ID)

		attrs := map[string]string{
			"entity_id":   "id",
			"entity_name": "name",
			"policies":    "policies",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityEntityPoliciesCheckLogical(resource string, policies []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resource]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := entity.JoinEntityID(id)
		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		if resp.Data["policies"] == nil && policies == nil {
			return nil
		}

		apiPolicies := resp.Data["policies"].([]interface{})

		if len(apiPolicies) != len(policies) {
			return fmt.Errorf("expected entity %s to have %d policies, has %d", id, len(policies), len(apiPolicies))
		}

		for _, apiPolicyI := range apiPolicies {
			apiPolicy := apiPolicyI.(string)

			found := false
			for _, policy := range policies {
				if apiPolicy == policy {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("unexpected policy %s in entity %s", apiPolicy, id)
			}
		}

		return nil
	}
}

func testAccIdentityEntityPoliciesConfigExclusive(entity string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  external_policies = true
}

resource "vault_identity_entity_policies" "policies" {
  entity_id = vault_identity_entity.entity.id
  policies = ["test"]
}`, entity)
}

func testAccIdentityEntityPoliciesConfigExclusiveUpdate(entity string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  external_policies = true
}

resource "vault_identity_entity_policies" "policies" {
  entity_id = vault_identity_entity.entity.id
  policies = ["dev", "test"]
}`, entity)
}

func testAccIdentityEntityPoliciesConfigNonExclusive(entity string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  external_policies = true
}

resource "vault_identity_entity_policies" "dev" {
	entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["dev"]
}


resource "vault_identity_entity_policies" "test" {
  entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["test"]
}
`, entity)
}

func testAccIdentityEntityPoliciesConfigNonExclusiveUpdate(entity string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  external_policies = true
}

resource "vault_identity_entity_policies" "dev" {
	entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["dev"]
}


resource "vault_identity_entity_policies" "test" {
  entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["foo"]
}
`, entity)
}

func testAccIdentityEntityPoliciesConfigNonExclusiveUpdateEntity(entity string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  external_policies = true
  metadata = {
    version = "1"
  }
}

resource "vault_identity_entity_policies" "dev" {
	entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["dev"]
}


resource "vault_identity_entity_policies" "test" {
  entity_id = vault_identity_entity.entity.id
  exclusive = false
  policies = ["foo"]
}
`, entity)
}
