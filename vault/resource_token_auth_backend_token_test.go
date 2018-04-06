package vault

import (
	"strconv"
	"testing"

	"fmt"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

func TestAccResourceTokenAuthBackendToken_basic(t *testing.T) {
	policy := acctest.RandomWithPrefix("test-policy")
	policyHash := strconv.Itoa(schema.HashString(policy))
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTokenAuthBackendToken_configBasic(policy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "display_name", "token-test-token"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies."+policyHash, policy),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "meta"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "role", ""),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "explicit_max_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "renewable", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "period_seconds", "3600"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "wrap"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "wrap_ttl_seconds"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "num_uses", "0"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "token"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "accessor"),
				),
			},
		},
	})
}

func TestAccResourceTokenAuthBackendToken_complete(t *testing.T) {
	policy := acctest.RandomWithPrefix("test-policy")
	policy2 := acctest.RandomWithPrefix("test-policy")
	policyHash := strconv.Itoa(schema.HashString(policy))
	policy2Hash := strconv.Itoa(schema.HashString(policy2))
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTokenAuthBackendToken_configComplete(policy, policy2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "display_name", "token-test-token"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies."+policyHash, policy),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies."+policy2Hash, policy2),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "meta.%", "2"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "meta.terraform", "test"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "meta.hello", "world"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "role", ""),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "ttl_seconds", "300"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "explicit_max_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "renewable", "true"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "period_seconds"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "wrap"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "wrap_ttl_seconds"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "num_uses", "10"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "token"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "accessor"),
				),
			},
		},
	})
}

func TestAccResourceTokenAuthBackendToken_wrapped(t *testing.T) {
	policy := acctest.RandomWithPrefix("test-policy")
	policyHash := strconv.Itoa(schema.HashString(policy))
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTokenAuthBackendToken_configWrapped(policy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "display_name", "token-test-token"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "policies."+policyHash, policy),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "meta"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "role"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "ttl_seconds"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "explicit_max_ttl_seconds"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "renewable", "false"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "period_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "wrap", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_token.test_token", "wrap_ttl_seconds", "300"),
					resource.TestCheckNoResourceAttr("vault_token_auth_backend_token.test_token", "num_uses"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "token"),
					resource.TestCheckResourceAttrSet("vault_token_auth_backend_token.test_token", "accessor"),
				),
			},
		},
	})
}

func testAccResourceTokenAuthBackendToken_configBasic(policy string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}

resource "vault_token_auth_backend_token" "test_token" {
	display_name = "test token"
	policies = ["${vault_policy.test.name}"]
	period_seconds = 3600
}`, policy)
}

func testAccResourceTokenAuthBackendToken_configComplete(policy, policy2 string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}

resource "vault_policy" "test2" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}

resource "vault_token_auth_backend_token" "test_token" {
	display_name = "test token"
	policies = ["${vault_policy.test.name}", "${vault_policy.test2.name}"]
	meta = {
		"terraform" = "test",
		"hello" = "world",
	}
	# TODO: set role when we can set up roles using the provider
	ttl_seconds = 300
	explicit_max_ttl_seconds = 3600
	renewable = true
	num_uses = 10
}`, policy, policy2)
}

func testAccResourceTokenAuthBackendToken_configWrapped(policy string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}

resource "vault_token_auth_backend_token" "test_token" {
	display_name = "test token"
	policies = ["${vault_policy.test.name}"]
	period_seconds = 3600
	renewable = false
	wrap = true
	wrap_ttl_seconds = 300
}`, policy)
}
