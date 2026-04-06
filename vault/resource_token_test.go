// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func testResourceTokenCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("token with accessor %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestResourceToken_basic(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "60s"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
				),
			},
		},
	})
}

func testResourceTokenConfig_basic() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ vault_policy.test.name ]
	ttl = "60s"
}`
}

func TestResourceToken_import(t *testing.T) {
	resourceName := "vault_token.test"
	roleName := "test-role-import"
	entityName := "test-entity-import"
	aliasName := "test-alias-import"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_import(roleName, entityName, aliasName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "60s"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "service"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleName, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntityAlias, aliasName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLeaseDuration),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,

				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{consts.FieldTTL, consts.FieldLeaseDuration, consts.FieldLeaseStarted, consts.FieldClientToken, consts.FieldRoleName, consts.FieldEntityAlias},
			},
		},
	})
}

func testResourceTokenConfig_import(roleName, entityName, aliasName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_auth_backend" "test" {
  type = "userpass"
  path = "userpass-test-import"
}

resource "vault_identity_entity" "test" {
  name = "%s"
}

resource "vault_identity_entity_alias" "test" {
  name           = "%s"
  mount_accessor = vault_auth_backend.test.accessor
  canonical_id   = vault_identity_entity.test.id
}

resource "vault_token_auth_backend_role" "test" {
  role_name              = "%s"
  allowed_policies       = [vault_policy.test.name]
  allowed_entity_aliases = [vault_identity_entity_alias.test.name]
}

resource "vault_token" "test" {
  policies     = [vault_policy.test.name]
  ttl          = "60s"
  type         = "service"
  role_name    = vault_token_auth_backend_role.test.role_name
  entity_alias = vault_identity_entity_alias.test.name
}
`, entityName, aliasName, roleName)
}

func TestResourceToken_full(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_full(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNoParent, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNoDefaultPolicy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRenewable, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "60s"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExplicitMaxTTL, "1h"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNumUses, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeaseDuration, "59"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
					resource.TestCheckResourceAttr(resourceName, "metadata.fizz", "buzz"),
				),
			},
		},
	})
}

func testResourceTokenConfig_full() string {
	return `
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
  policies          = [vault_policy.test.name]
  no_parent         = true
  no_default_policy = true
  renewable         = true
  ttl               = "60s"
  explicit_max_ttl  = "1h"
  display_name      = "test"
  num_uses          = 1
  period            = 0
  metadata = {
    fizz = "buzz"
  }
}
`
}

func TestResourceToken_lookup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_lookup(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenLookup("vault_token.test"),
				),
			},
		},
	})
}

func testResourceTokenConfig_lookup() string {
	return `
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
  policies = [vault_policy.test.name]
  ttl      = "60s"
}
`
}

func TestResourceToken_expire(t *testing.T) {
	t.Skip("skipping, because it's flaky in CI and there's a long time.Sleep call")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", consts.FieldTTL, "5s"),
					resource.TestCheckResourceAttr("vault_token.test", consts.FieldLeaseDuration, "4"),
					resource.TestCheckResourceAttrSet("vault_token.test", consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet("vault_token.test", consts.FieldClientToken),
				),
			},
			{
				Config:   testResourceTokenConfig_expire(),
				PlanOnly: true,
			},
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenWaitExpireTime("vault_token.test"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config:  testResourceTokenConfig_expire(),
				Destroy: true,
			},
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", consts.FieldTTL, "5s"),
					resource.TestCheckResourceAttr("vault_token.test", consts.FieldLeaseDuration, "4"),
					resource.TestCheckResourceAttrSet("vault_token.test", consts.FieldLeaseStarted),
					resource.TestCheckResourceAttrSet("vault_token.test", consts.FieldClientToken),
				),
			},
		},
	})
}

func testResourceTokenConfig_expire() string {
	return `
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
  policies = [vault_policy.test.name]
  ttl      = "5s"
}
`
}

func TestResourceToken_renew(t *testing.T) {
	t.Skip("skipping, because it's flaky in CI and there's a long time.Sleep call")
	resourceName := "vault_token.test"

	commonCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20s"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldRenewMinLease, "15"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldRenewIncrement, "30"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLeaseDuration, "19"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "1"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".0", "test"),
	}
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_renew(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(commonCheckFuncs,
						testResourceTokenCheckExpireTime(resourceName),
						resource.TestCheckResourceAttr(resourceName, consts.FieldRenewable, "true"))...,
				),
			},
			{
				Config:   testResourceTokenConfig_renew(true),
				PlanOnly: true,
			},
			{
				Config: testResourceTokenConfig_renew(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(commonCheckFuncs,
						testResourceTokenWaitRenewMinLeaseTime(resourceName),
						resource.TestCheckResourceAttr(resourceName, consts.FieldRenewable, "true"))...,
				),
			},
			{
				Config:  testResourceTokenConfig_renew(true),
				Destroy: true,
			},
			{
				Config: testResourceTokenConfig_renew(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(commonCheckFuncs,
						testResourceTokenCheckExpireTime(resourceName),
						resource.TestCheckResourceAttr(resourceName, consts.FieldRenewable, "true"))...,
				),
			},
			{
				Config: testResourceTokenConfig_renew(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(commonCheckFuncs,
						testResourceTokenCheckExpireTime(resourceName),
						resource.TestCheckResourceAttr(resourceName, consts.FieldRenewable, "false"))...,
				),
			},
		},
	})
}

func testResourceTokenConfig_renew(renewable bool) string {
	config := fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
  policies = [
    vault_policy.test.name,
  ]
  renewable       = "%t"
  ttl             = "20s"
  renew_min_lease = 15
  renew_increment = 30
}
`, renewable)

	return config
}

func testResourceTokenLookup(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		return nil
	}
}

func testResourceTokenCheckExpireTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		token, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		expireTime, err := time.Parse(time.RFC3339, token.Data["expire_time"].(string))
		if err != nil {
			return fmt.Errorf("Invalid expire_time value: %s", err)
		}

		startedTime, err := time.Parse(time.RFC3339, rs.Primary.Attributes[consts.FieldLeaseStarted])
		if err != nil {
			return fmt.Errorf("Invalid lease_started value: %s", err)
		}

		if startedTime.After(time.Now()) {
			return fmt.Errorf("Invalid lease_started value: %s", "time is in the future")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes[consts.FieldLeaseDuration])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		leaseTime := startedTime.Add(time.Duration(leaseDuration) * time.Second)

		if leaseTime.After(expireTime) {
			return fmt.Errorf("Lease time %s is after expire time %s", leaseTime, expireTime)
		}

		return nil
	}
}

func testResourceTokenWaitExpireTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes[consts.FieldLeaseDuration])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		time.Sleep(time.Duration(leaseDuration+1) * time.Second)

		return nil
	}
}

func testResourceTokenWaitRenewMinLeaseTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		token, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		if !token.Data[consts.FieldRenewable].(bool) {
			return fmt.Errorf("Token could not be renewed")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes[consts.FieldLeaseDuration])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		renewMinLease, err := strconv.Atoi(rs.Primary.Attributes[consts.FieldRenewMinLease])
		if err != nil {
			return fmt.Errorf("Invalid renew_min_lease value: %s", err)
		}

		time.Sleep(time.Duration(leaseDuration-renewMinLease+1) * time.Second)

		return nil
	}
}

func TestResourceToken_withType(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_withType("service"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "service"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{consts.FieldTTL, consts.FieldLeaseDuration, consts.FieldLeaseStarted, consts.FieldClientToken, consts.FieldEntityAlias},
			},
		},
	})
}

func TestResourceToken_withTypeBatch(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_withType("batch"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "batch"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
				),
			},
			// Note: Batch tokens cannot be imported via accessor because they don't have accessors.
			// The resource uses RequestID as the ID for batch tokens, but ImportStatePassthrough
			// doesn't work for batch tokens since they can't be looked up by the ID we store.
			// This is a known limitation - batch tokens are not importable.
		},
	})
}

func testResourceTokenConfig_withType(tokenType string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
  policies = [vault_policy.test.name]
  type     = "%s"
}
`, tokenType)
}

func TestResourceToken_withEntityAlias(t *testing.T) {
	resourceName := "vault_token.test"
	roleName := "test-role"
	entityName := "test-entity"
	aliasName := "test-alias"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_withEntityAlias(roleName, entityName, aliasName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleName, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntityAlias, aliasName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),
				),
			},
		},
	})
}

func testResourceTokenConfig_withEntityAlias(roleName, entityName, aliasName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = "test"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_auth_backend" "test" {
  type = "userpass"
  path = "userpass-test"
}

resource "vault_identity_entity" "test" {
  name = "%s"
}

resource "vault_identity_entity_alias" "test" {
  name           = "%s"
  mount_accessor = vault_auth_backend.test.accessor
  canonical_id   = vault_identity_entity.test.id
}

resource "vault_token_auth_backend_role" "test" {
  role_name              = "%s"
  allowed_policies       = [vault_policy.test.name]
  allowed_entity_aliases = [vault_identity_entity_alias.test.name]
}

resource "vault_token" "test" {
  policies     = [vault_policy.test.name]
  role_name    = vault_token_auth_backend_role.test.role_name
  entity_alias = vault_identity_entity_alias.test.name
}
`, entityName, aliasName, roleName)
}

func TestResourceToken_batchTokenAutoDetectionViaRole(t *testing.T) {
	resourceName := "vault_token.test"
	roleName := "batch-vault-role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_batchTokenAutoDetectionViaRole(roleName),
				Check: resource.ComposeTestCheckFunc(
					// Verify the token was actually created
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientToken),

					// Even though Vault issued a batch token (hvb...), the provider
					// didn't explicitly update the 'type' field in the state during Create.
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "batch"),
				),
			},
			{
				// Trigger a refresh to see if the provider tries to
				// perform a LookupAccessor (which it shouldn't for batch)
				Config:   testResourceTokenConfig_batchTokenAutoDetectionViaRole(roleName),
				PlanOnly: true,
			},
		},
	})
}

func testResourceTokenConfig_batchTokenAutoDetectionViaRole(roleName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = "test"
  policy = "path \"secret/*\" { capabilities = [\"read\"] }"
}

resource "vault_token_auth_backend_role" "batch" {
  role_name        = "%s"
  token_type       = "batch"
  orphan           = true   # Batch tokens must be orphans
  renewable        = false  # Batch tokens cannot be renewable
  allowed_policies = [vault_policy.test.name]
}

resource "vault_token" "test" {
  role_name = vault_token_auth_backend_role.batch.role_name
  # No 'type' specified here, forcing the provider to auto-detect it from the role
}
`, roleName)
}
