// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	// "regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccOktaAuthBackend_basic(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-basic-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-import-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
			),
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
			),
		},
	})
}

func TestAccOktaAuthBackend_groups_optional(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-group-optional")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-okta")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-okta-updated")

	organization := "example"
	resourceName := "vault_okta_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
			),
		},
	})
}

func TestAccOktaAuthBackend_TokenFields(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-okta")
	organization := "example"
	resourceName := "vault_okta_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
			),
		},
	})
}

func TestAccOktaAuthBackend_tuning(t *testing.T) {
	t.Parallel()
	testutil.SkipTestAcc(t)

	organization := "example"
	path := acctest.RandomWithPrefix("okta-tune-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeOkta, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_tune_partial(path, organization),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
				),
			},
			{
				Config: testAccOktaAuthConfig_tune_full(path, organization),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "batch"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
				),
			},
		},
	})
}

func TestAccOktaAuthBackend_importTune(t *testing.T) {
	t.Parallel()
	testutil.SkipTestAcc(t)

	organization := "example"
	path := acctest.RandomWithPrefix("okta-import-tune-")
	resourceType := "vault_okta_auth_backend"
	resourceName := resourceType + ".test"

	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeOkta, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_tune_full(path, organization),
				Check: testutil.TestAccCheckAuthMountExists(resourceName,
					&resAuth,
					testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldToken, consts.FieldDisableRemount),
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

func testAccOktaAuthConfig_tune_partial(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
	description = "Testing the Terraform okta auth backend"
	path = "%s"
	organization = "%s"
	token = "this must be kept secret"
	tune {
		audit_non_hmac_request_keys = ["key1"]
		audit_non_hmac_response_keys = ["key3"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, path, organization)
}

func testAccOktaAuthConfig_tune_full(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
	description = "Testing the Terraform okta auth backend"
	path = "%s"
	organization = "%s"
	token = "this must be kept secret"
	tune {
		default_lease_ttl = "10m"
		max_lease_ttl = "20m"
		listing_visibility = "hidden"
		token_type = "batch"
		audit_non_hmac_request_keys = ["key1", "key2"]
		audit_non_hmac_response_keys = ["key3", "key4"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, path, organization)
}
