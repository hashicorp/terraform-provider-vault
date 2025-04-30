// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccOktaAuthBackend_basic(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-basic-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeOkta, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, TokenFieldTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "example"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "Testing the Terraform okta auth backend"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					resource.TestCheckResourceAttr(resourceName, "group.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "group.0.group_name", "dummy"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.1", "one"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.2", "two"),
					resource.TestCheckResourceAttr(resourceName, "user.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.username", "foo"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.0", "dummy"),
				),
			},
			{
				Config: testAccOktaAuthConfig_updated(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "group.0.group_name", "example"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.1", "four"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.2", "three"),
					resource.TestCheckResourceAttr(resourceName, "user.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.username", "bar"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.0", "example"),
				),
			},
		},
	})
}

func TestAccOktaAuthBackend_import(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-import-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeOkta, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, TokenFieldTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "example"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "Testing the Terraform okta auth backend"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					resource.TestCheckResourceAttr(resourceName, "group.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "group.0.group_name", "dummy"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.1", "one"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.2", "two"),
					resource.TestCheckResourceAttr(resourceName, "user.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.username", "foo"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.0", "dummy"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token",
				"disable_remount",
				"ttl",
				"max_ttl"),
			{
				Config: testAccOktaAuthConfig_updated(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "group.0.group_name", "example"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.1", "four"),
					resource.TestCheckResourceAttr(resourceName, "group.0.policies.2", "three"),
					resource.TestCheckResourceAttr(resourceName, "user.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.username", "bar"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.groups.0", "example"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token",
				"disable_remount",
				"ttl",
				"max_ttl"),
		},
	})
}

func TestAccOktaAuthBackend_groups_optional(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-group-optional")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeOkta, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_groups_optional(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "user.0.username", "bar"),
					resource.TestCheckResourceAttr(resourceName, "user.0.policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "user.0.policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "user.0.policies.1", "eng"),
				),
			},
		},
	})
}

func TestAccOktaAuthBackend_remount(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-okta")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-okta-updated")

	organization := "example"
	resourceName := "vault_okta_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, TokenFieldTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "example"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "Testing the Terraform okta auth backend"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				Config: testAccOktaAuthConfig_basic(updatedPath, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, TokenFieldTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganization, "example"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "Testing the Terraform okta auth backend"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token",
				"disable_remount",
				"ttl",
				"max_ttl"),
		},
	})
}

func TestAccOktaAuthBackend_TokenFields(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-okta")
	organization := "example"
	resourceName := "vault_okta_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_tokenFields(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.0", "policy_a"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.1", "policy_b"),
					resource.TestCheckResourceAttr(resourceName, TokenFieldTTL, "300"),
					resource.TestCheckResourceAttr(resourceName, TokenFieldMaxTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, TokenFieldNoDefaultPolicy, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token",
				"disable_remount",
				"ttl",
				"max_ttl"),
		},
	})
}

func testAccOktaAuthConfig_basic(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    token_ttl = 3600
    group {
        group_name = "dummy"
        policies = ["one", "two", "default"]
    }
    user {
        username = "foo"
        groups = ["dummy"]
    }
}
`, path, organization)
}

func testAccOktaAuthConfig_updated(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    group {
        group_name = "example"
        policies = ["three", "four", "default"]
    }
    user {
        username = "bar"
        groups = ["example"]
    }
}
`, path, organization)
}

func testAccOktaAuthConfig_groups_optional(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    user {
        username = "bar"
        policies   = ["eng", "default"]
    }
}
`, path, organization)
}

func testAccOktaAuthConfig_tokenFields(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path           = "%s"
    organization   = "%s"
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["policy_a", "policy_b"]
}
`, path, organization)
}
