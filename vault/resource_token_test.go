package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
	"testing"
	"time"
)

func testResourceTokenCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token" {
			continue
		}
		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("token with accessor %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestResourceToken_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
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
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_role(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_role(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "role_name", "test"),
				),
			},
		},
	})
}

func testResourceTokenConfig_role() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token_role" "test" {
	name = "test"
}

resource "vault_token" "test" {
	role_name = "${vault_token_role.test.name}"
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_lookup(t *testing.T) {

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
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
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token_role" "test" {
	name = "test"
}

resource "vault_token" "test" {
	role_name = "${vault_token_role.test.name}"
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_expire(t *testing.T) {

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "60s"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "60"),
				),
			},
		},
	})
}

func testResourceTokenConfig_expire() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token_role" "test" {
	name = "test"
}

resource "vault_token" "test" {
	role_name = "${vault_token_role.test.name}"
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_renew(t *testing.T) {

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_renew(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "24h"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_min_lease", "7200"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_increment", "86400"),
				),
			},
		},
	})
}

func testResourceTokenConfig_renew() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token_role" "test" {
	name = "test"
}

resource "vault_token" "test" {
	role_name = "${vault_token_role.test.name}"
	policies = [ "${vault_policy.test.name}" ]
	renewable = true
	ttl = "24h"
	renew_min_lease = 7200
	renew_increment = 86400
}`
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

		client := testProvider.Meta().(*api.Client)

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

		client := testProvider.Meta().(*api.Client)

		token, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		expireTime, err := time.Parse(time.RFC3339, token.Data["expire_time"].(string))
		if err != nil {
			return fmt.Errorf("Invalid expire_time value: %s", err)
		}

		startedTime, err := time.Parse(time.RFC3339, rs.Primary.Attributes["lease_started"])
		if err != nil {
			return fmt.Errorf("Invalid lease_started value: %s", err)
		}

		ttl, err := strconv.Atoi(rs.Primary.Attributes["lease_duration"])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		leaseTime := startedTime.Add(time.Duration(ttl) * time.Second)

		if leaseTime.After(expireTime) {
			return fmt.Errorf("Lease time %s is after expire time %s", leaseTime, expireTime)
		}

		return nil
	}
}
