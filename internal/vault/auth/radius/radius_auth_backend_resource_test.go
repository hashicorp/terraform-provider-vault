// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccRadiusAuthBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("radius")
	resourceType := "vault_radius_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "10"),
				),
			},
			{
				Config: testAccRadiusAuthBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "radius.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1813"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "15"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "dev"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "1200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "3000"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        path,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO, consts.FieldRadiusSecretWOVersion},
			},
		},
	})
}

func TestAccRadiusAuthBackend_secretWO(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-wo")
	resourceType := "vault_radius_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_secretWO(path, "testsecret", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusSecretWOVersion, "1"),
					// Verify write-only secret is not returned/stored in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldRadiusSecretWO),
				),
			},
			{
				// Update write-only secret by changing version
				Config: testAccRadiusAuthBackendConfig_secretWO(path, "updatedsecret", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusSecretWOVersion, "2"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        path,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO, consts.FieldRadiusSecretWOVersion},
			},
		},
	})
}

func testAccRadiusAuthBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
}
`, path)
}

func testAccRadiusAuthBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                       = "%s"
  host                       = "radius.example.com"
  port                       = 1813
  secret_wo                  = "updatedsecret"
  secret_wo_version          = 2
  unregistered_user_policies = ["default", "dev"]
  dial_timeout               = 15
  nas_port                   = 20
  token_ttl                  = 1200
  token_max_ttl              = 3000
}
`, path)
}

func testAccRadiusAuthBackendConfig_secretWO(path, secret string, version int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "%s"
  secret_wo_version = %d
}
`, path, secret, version)
}

// TestAccRadiusAuthBackend_invalid tests error cases for the RADIUS auth backend
func TestAccRadiusAuthBackend_invalid(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-invalid")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Missing required host field
			{
				Config:      testAccRadiusAuthBackendConfig_missingHost(path),
				ExpectError: regexp.MustCompile(`The argument "host" is required`),
			},
			// Missing required secret_wo field
			{
				Config:      testAccRadiusAuthBackendConfig_missingSecret(path),
				ExpectError: regexp.MustCompile(`The argument "secret_wo" is required`),
			},
			// Empty host parameter
			{
				Config:      testAccRadiusAuthBackendConfig_emptyHost(path),
				ExpectError: regexp.MustCompile("config parameter `host` cannot be empty"),
			},
			// Empty secret parameter
			{
				Config:      testAccRadiusAuthBackendConfig_emptySecret(path),
				ExpectError: regexp.MustCompile("config parameter `secret` cannot be empty"),
			},
			// Invalid port - non-integer value
			{
				Config:      testAccRadiusAuthBackendConfig_invalidPortType(path),
				ExpectError: regexp.MustCompile(`Inappropriate value for attribute "port"`),
			},
			// Invalid dial_timeout - negative value
			{
				Config:      testAccRadiusAuthBackendConfig_negativeDialTimeout(path),
				ExpectError: regexp.MustCompile(`cannot provide negative`),
			},
			// Invalid token_ttl - negative value
			{
				Config:      testAccRadiusAuthBackendConfig_negativeTokenTTL(path),
				ExpectError: regexp.MustCompile(`cannot provide negative`),
			},
			// Invalid token_ttl - malformed duration string
			{
				Config:      testAccRadiusAuthBackendConfig_malformedTokenTTL(path),
				ExpectError: regexp.MustCompile(`Inappropriate value for attribute "token_ttl"`),
			},
			// Invalid CIDR block format
			{
				Config:      testAccRadiusAuthBackendConfig_invalidCIDR(path),
				ExpectError: regexp.MustCompile(`Unable to convert`),
			},
			// Invalid token type
			{
				Config:      testAccRadiusAuthBackendConfig_invalidTokenType(path),
				ExpectError: regexp.MustCompile(`invalid 'token_type' value`),
			},
			// Invalid token_no_default_policy type
			{
				Config:      testAccRadiusAuthBackendConfig_invalidTokenNoDefaultPolicyType(path),
				ExpectError: regexp.MustCompile(`Inappropriate value for attribute "token_no_default_policy"`),
			},
			// Unknown/extra parameters
			{
				Config:      testAccRadiusAuthBackendConfig_unknownParameter(path),
				ExpectError: regexp.MustCompile(`An argument named "unknown_param" is not expected here`),
			},
			// Null value for required parameter
			{
				Config:      testAccRadiusAuthBackendConfig_nullHost(path),
				ExpectError: regexp.MustCompile(`Must set a configuration value for the host attribute`),
			},
		},
	})
}

func testAccRadiusAuthBackendConfig_missingHost(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path      = "%s"
  secret_wo = "testsecret"
}
`, path)
}

func testAccRadiusAuthBackendConfig_missingSecret(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path = "%s"
  host = "127.0.0.1"
}
`, path)
}

func testAccRadiusAuthBackendConfig_emptyHost(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = ""
  secret_wo         = "testsecret"
  secret_wo_version = 1
}
`, path)
}

func testAccRadiusAuthBackendConfig_emptySecret(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = ""
  secret_wo_version = 1
}
`, path)
}

func testAccRadiusAuthBackendConfig_invalidPortType(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  port              = "abc"
}
`, path)
}

func testAccRadiusAuthBackendConfig_negativeDialTimeout(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  dial_timeout      = -1
}
`, path)
}

func testAccRadiusAuthBackendConfig_negativeTokenTTL(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_ttl         = -1
}
`, path)
}

func testAccRadiusAuthBackendConfig_malformedTokenTTL(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_ttl         = "abc"
}
`, path)
}

func testAccRadiusAuthBackendConfig_invalidCIDR(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_bound_cidrs = ["invalid-cidr"]
}
`, path)
}

func testAccRadiusAuthBackendConfig_invalidTokenType(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_type        = "invalid"
}
`, path)
}

func testAccRadiusAuthBackendConfig_invalidTokenNoDefaultPolicyType(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                    = "%s"
  host                    = "127.0.0.1"
  secret_wo               = "testsecret"
  secret_wo_version       = 1
  token_no_default_policy = "invalid"
}
`, path)
}

func testAccRadiusAuthBackendConfig_unknownParameter(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  unknown_param     = "value"
}
`, path)
}

func testAccRadiusAuthBackendConfig_nullHost(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = null
  secret_wo         = "testsecret"
  secret_wo_version = 1
}
`, path)
}

// TestAccRadiusAuthBackend_customDialTimeout tests custom dial timeout configuration
func TestAccRadiusAuthBackend_customDialTimeout(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-timeout")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_customDialTimeout(path, 30),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "30"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_customNASPort tests custom NAS port configuration
func TestAccRadiusAuthBackend_customNASPort(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-nas")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_customNASPort(path, 50),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "50"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenTTL tests token TTL configuration
func TestAccRadiusAuthBackend_tokenTTL(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-ttl")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenTTL(path, 3600, 14400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "14400"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenPolicies tests token policies configuration
func TestAccRadiusAuthBackend_tokenPolicies(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-policies")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenPolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy3"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenBoundCIDRs tests token bound CIDRs configuration
func TestAccRadiusAuthBackend_tokenBoundCIDRs(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-cidrs")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenBoundCIDRs(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "10.0.0.0/8"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "172.16.0.0/12"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "192.168.0.0/16"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenNoDefaultPolicy tests token_no_default_policy configuration
func TestAccRadiusAuthBackend_tokenNoDefaultPolicy(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-nodefault")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenNoDefaultPolicy(path, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
				),
			},
			{
				Config: testAccRadiusAuthBackendConfig_tokenNoDefaultPolicy(path, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "false"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenNumUses tests token_num_uses configuration
func TestAccRadiusAuthBackend_tokenNumUses(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-numuses")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenNumUses(path, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "10"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenPeriod tests token_period configuration
func TestAccRadiusAuthBackend_tokenPeriod(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-period")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_tokenPeriod(path, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPeriod, "3600"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenType tests token_type configuration
func TestAccRadiusAuthBackend_tokenType(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-type")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test service token type
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "service"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
				),
			},
			// Test batch token type
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "batch"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "batch"),
				),
			},
			// Test default token type
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "default"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "default"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_removeUnregisteredUserPolicies tests that removing
// unregistered_user_policies from config clears policies in Vault
func TestAccRadiusAuthBackend_removeUnregisteredUserPolicies(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-remove-pol")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with policies
				Config: testAccRadiusAuthBackendConfig_withPolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "policy1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "policy2"),
				),
			},
			{
				// Step 2: Remove policies from config - should clear in Vault
				Config: testAccRadiusAuthBackendConfig_withoutPolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					// Verify unregistered_user_policies is null (cleared)
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_multiplePolicies tests comma-separated policy list
func TestAccRadiusAuthBackend_multiplePolicies(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-multi-pol")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_multiplePolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "readonly"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "audit"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_fullConfig tests complete configuration with all parameters
func TestAccRadiusAuthBackend_fullConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-full")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_full(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "radius.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "50"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        path,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO, consts.FieldRadiusSecretWOVersion},
			},
		},
	})
}

// Config helper functions

func testAccRadiusAuthBackendConfig_customDialTimeout(path string, timeout int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  dial_timeout      = %d
}
`, path, timeout)
}

func testAccRadiusAuthBackendConfig_customNASPort(path string, nasPort int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  nas_port          = %d
}
`, path, nasPort)
}

func testAccRadiusAuthBackendConfig_tokenTTL(path string, ttl, maxTTL int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_ttl         = %d
  token_max_ttl     = %d
}
`, path, ttl, maxTTL)
}

func testAccRadiusAuthBackendConfig_tokenPolicies(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_policies    = ["policy1", "policy2", "policy3"]
}
`, path)
}

func testAccRadiusAuthBackendConfig_tokenBoundCIDRs(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_bound_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}
`, path)
}

func testAccRadiusAuthBackendConfig_tokenNoDefaultPolicy(path string, noDefault bool) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                    = "%s"
  host                    = "127.0.0.1"
  secret_wo               = "testsecret"
  secret_wo_version       = 1
  token_no_default_policy = %t
}
`, path, noDefault)
}

func testAccRadiusAuthBackendConfig_tokenNumUses(path string, numUses int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_num_uses    = %d
}
`, path, numUses)
}

func testAccRadiusAuthBackendConfig_tokenPeriod(path string, period int) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_period      = %d
}
`, path, period)
}

func testAccRadiusAuthBackendConfig_tokenType(path, tokenType string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
  token_type        = "%s"
}
`, path, tokenType)
}

func testAccRadiusAuthBackendConfig_multiplePolicies(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                       = "%s"
  host                       = "127.0.0.1"
  secret_wo                  = "testsecret"
  secret_wo_version          = 1
  unregistered_user_policies = ["default", "readonly", "audit"]
}
`, path)
}

func testAccRadiusAuthBackendConfig_withPolicies(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                       = "%s"
  host                       = "127.0.0.1"
  secret_wo                  = "testsecret"
  secret_wo_version          = 1
  unregistered_user_policies = ["policy1", "policy2"]
}
`, path)
}

func testAccRadiusAuthBackendConfig_withoutPolicies(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path              = "%s"
  host              = "127.0.0.1"
  secret_wo         = "testsecret"
  secret_wo_version = 1
}
`, path)
}

func testAccRadiusAuthBackendConfig_full(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  path                       = "%s"
  host                       = "radius.example.com"
  port                       = 1812
  secret_wo                  = "testsecret"
  secret_wo_version          = 1
  dial_timeout               = 30
  nas_port                   = 50
  unregistered_user_policies = ["default", "dev"]
  token_ttl                  = 3600
  token_max_ttl              = 7200
  token_policies             = ["admin", "ops"]
  token_bound_cidrs          = ["10.0.0.0/8", "192.168.0.0/16"]
  token_no_default_policy    = true
  token_num_uses             = 5
  token_type                 = "service"
}
`, path)
}
