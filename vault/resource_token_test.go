// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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

func TestResourceToken_import(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{consts.FieldTTL, consts.FieldLeaseDuration, consts.FieldLeaseStarted, consts.FieldClientToken},
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

func TestResourceToken_full(t *testing.T) {
	resourceName := "vault_token.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
