// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccRadiusAuthBackendConfig_basic(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "10"),
				),
			},
			{
				Config: testAccRadiusAuthBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
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
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO},
			},
		},
	})
}

func testAccRadiusAuthBackendMountConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "radius"
	path = "%s"
}
`, path)
}

func testAccRadiusAuthBackendConfig(path, body string) string {
	return fmt.Sprintf(`
%s

resource "vault_radius_auth_backend" "test" {
	mount = vault_auth_backend.test.path
%s
}
`, testAccRadiusAuthBackendMountConfig(path), body)
}

func testAccRadiusAuthBackendInvalidConfig(path, body string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
	mount = "%s"
%s
}
`, path, body)
}

func testAccRadiusAuthBackendConfig_basic(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_updated(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                       = "radius.example.com"
	port                       = 1813
	secret_wo                  = "updatedsecret"
	unregistered_user_policies = ["default", "dev"]
	dial_timeout               = 15
	nas_port                   = 20
	token_ttl                  = 1200
	token_max_ttl              = 3000
`)
}

// TestAccRadiusAuthBackend_secretWO tests that the write-only secret_wo attribute is not stored in state
func TestAccRadiusAuthBackendConfig_secretWO(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-wo")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					// Verify write-only secret is not stored in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldRadiusSecretWO),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_validationErrors tests Terraform-side validation errors.
func TestAccRadiusAuthBackendConfig_validationErrors(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-invalid")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Missing required host field
			{
				Config:      testAccRadiusAuthBackendConfig_missingHost(path),
				ExpectError: regexp.MustCompile(`(attribute|argument) "host" is required`),
			},
			// Missing required secret_wo field
			{
				Config:      testAccRadiusAuthBackendConfig_missingSecret(path),
				ExpectError: regexp.MustCompile(`(attribute|argument) "secret_wo" is required`),
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
			// Final valid config so post-test destroy can clean up any mounts created by
			// mounted invalid-config cases above.
			{
				Config: testAccRadiusAuthBackendMountConfig(path),
			},
		},
	})
}

// TestAccRadiusAuthBackend_runtimeErrors tests Vault-side runtime errors.
func TestAccRadiusAuthBackendConfig_runtimeErrors(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-runtime")
	nonExistentPath := acctest.RandomWithPrefix("radius-missing")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRadiusAuthBackendConfig_emptyHost(path),
				ExpectError: regexp.MustCompile("config parameter `host` cannot be empty"),
			},
			{
				Config:      testAccRadiusAuthBackendConfig_emptySecret(path),
				ExpectError: regexp.MustCompile("config parameter `secret` cannot be empty"),
			},
			{
				Config:      testAccRadiusAuthBackendConfig_nonExistentBackend(nonExistentPath),
				ExpectError: regexp.MustCompile(`error writing|no handler for route|unsupported path`),
			},
		},
	})
}

// TestAccRadiusAuthBackend_importErrors tests invalid import identifiers.
func TestAccRadiusAuthBackendConfig_importErrors(t *testing.T) {
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccRadiusAuthBackendConfig_basic("test"),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "invalid-import-id",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			{
				Config:            testAccRadiusAuthBackendConfig_basic("test"),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "auth/radius",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			{
				Config:            testAccRadiusAuthBackendConfig_basic("test"),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "radius/config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			{
				Config:            testAccRadiusAuthBackendConfig_basic("test"),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "auth//config",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
		},
	})
}

func testAccRadiusAuthBackendConfig_missingHost(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_missingSecret(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host = "127.0.0.1"
`)
}

func testAccRadiusAuthBackendConfig_emptyHost(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = ""
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_emptySecret(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = "127.0.0.1"
	secret_wo = ""
`)
}

func testAccRadiusAuthBackendConfig_nonExistentBackend(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_invalidPortType(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
	port      = "abc"
`)
}

func testAccRadiusAuthBackendConfig_negativeDialTimeout(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host         = "127.0.0.1"
	secret_wo    = "testsecret"
	dial_timeout = -1
`)
}

func testAccRadiusAuthBackendConfig_negativeTokenTTL(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
	token_ttl = -1
`)
}

func testAccRadiusAuthBackendConfig_malformedTokenTTL(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
	token_ttl = "abc"
`)
}

func testAccRadiusAuthBackendConfig_invalidCIDR(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host              = "127.0.0.1"
	secret_wo         = "testsecret"
	token_bound_cidrs = ["invalid-cidr"]
`)
}

func testAccRadiusAuthBackendConfig_invalidTokenType(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host       = "127.0.0.1"
	secret_wo  = "testsecret"
	token_type = "invalid"
`)
}

func testAccRadiusAuthBackendConfig_invalidTokenNoDefaultPolicyType(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host                    = "127.0.0.1"
	secret_wo               = "testsecret"
	token_no_default_policy = "invalid"
`)
}

func testAccRadiusAuthBackendConfig_unknownParameter(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host          = "127.0.0.1"
	secret_wo     = "testsecret"
	unknown_param = "value"
`)
}

func testAccRadiusAuthBackendConfig_nullHost(path string) string {
	return testAccRadiusAuthBackendInvalidConfig(path, `
	host      = null
	secret_wo = "testsecret"
`)
}

// TestAccRadiusAuthBackend_customDialTimeout tests custom dial timeout configuration
func TestAccRadiusAuthBackendConfig_customDialTimeout(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-timeout")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_customDialTimeout(path, 30),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusDialTimeout, "30"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_customNASPort tests custom NAS port configuration
func TestAccRadiusAuthBackendConfig_customNASPort(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-nas")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_customNASPort(path, 50),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusNASPort, "50"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_tokenFields tests all token-related fields.
func TestAccRadiusAuthBackendConfig_tokenFields(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-token")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Test token TTL fields
			{
				Config: testAccRadiusAuthBackendConfig_tokenTTL(path, 3600, 14400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "14400"),
				),
			},
			// Step 2: Test token policies
			{
				Config: testAccRadiusAuthBackendConfig_tokenPolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "policy3"),
				),
			},
			// Step 3: Test token bound CIDRs
			{
				Config: testAccRadiusAuthBackendConfig_tokenBoundCIDRs(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "10.0.0.0/8"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "172.16.0.0/12"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "192.168.0.0/16"),
				),
			},
			// Step 4: Test token_no_default_policy = true
			{
				Config: testAccRadiusAuthBackendConfig_withTokenNoDefaultPolicy(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
				),
			},
			// Step 5: Test token_no_default_policy removal (reset to default)
			{
				Config: testAccRadiusAuthBackendConfig_withoutTokenNoDefaultPolicy(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy),
				),
			},
			// Step 6: Test token_num_uses
			{
				Config: testAccRadiusAuthBackendConfig_tokenNumUses(path, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "10"),
				),
			},
			// Step 7: Test token_period
			{
				Config: testAccRadiusAuthBackendConfig_tokenPeriod(path, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPeriod, "3600"),
				),
			},
			// Step 8: Test token_type = service
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "service"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
				),
			},
			// Step 9: Test token_type = batch
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "batch"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "batch"),
				),
			},
			// Step 10: Test token_type = default
			{
				Config: testAccRadiusAuthBackendConfig_tokenType(path, "default"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "default"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_aliasMetadata tests alias_metadata field.
// This test requires Vault Enterprise 1.21+ for alias_metadata support.
func TestAccRadiusAuthBackendConfig_aliasMetadata(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-alias")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test alias_metadata
			{
				Config: testAccRadiusAuthBackendConfig_aliasMetadata(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".%", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".foo", "bar"),
				),
			},
			// Test all token fields together including alias_metadata
			{
				Config: testAccRadiusAuthBackendConfig_allTokenFields(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPeriod, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".%", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".foo", "bar"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_removeUnregisteredUserPolicies tests that removing
// unregistered_user_policies from config clears policies in Vault
func TestAccRadiusAuthBackendConfig_removeUnregisteredUserPolicies(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "policy1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".*", "policy2"),
				),
			},
			{
				// Step 2: Remove policies from config - should clear in Vault
				Config: testAccRadiusAuthBackendConfig_withoutPolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					// Verify unregistered_user_policies is null (cleared)
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldRadiusUnregisteredUserPolicies+".#"),
				),
			},
		},
	})
}

// TestAccRadiusAuthBackend_multiplePolicies tests comma-separated policy list
func TestAccRadiusAuthBackendConfig_multiplePolicies(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-multi-pol")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_multiplePolicies(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
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
func TestAccRadiusAuthBackendConfig_fullConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-full")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_full(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
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
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO},
			},
		},
	})
}

// Config helper functions

func testAccRadiusAuthBackendConfig_customDialTimeout(path string, timeout int) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host         = "127.0.0.1"
	secret_wo    = "testsecret"
	dial_timeout = %d
`, timeout))
}

func testAccRadiusAuthBackendConfig_customNASPort(path string, nasPort int) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host      = "127.0.0.1"
	secret_wo = "testsecret"
	nas_port  = %d
`, nasPort))
}

func testAccRadiusAuthBackendConfig_tokenTTL(path string, ttl, maxTTL int) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host          = "127.0.0.1"
	secret_wo     = "testsecret"
	token_ttl     = %d
	token_max_ttl = %d
`, ttl, maxTTL))
}

func testAccRadiusAuthBackendConfig_tokenPolicies(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host           = "127.0.0.1"
	secret_wo      = "testsecret"
	token_policies = ["policy1", "policy2", "policy3"]
`)
}

func testAccRadiusAuthBackendConfig_tokenBoundCIDRs(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host              = "127.0.0.1"
	secret_wo         = "testsecret"
	token_bound_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
`)
}

func testAccRadiusAuthBackendConfig_withTokenNoDefaultPolicy(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                    = "127.0.0.1"
	secret_wo               = "testsecret"
	token_no_default_policy = true
`)
}

func testAccRadiusAuthBackendConfig_withoutTokenNoDefaultPolicy(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_tokenNumUses(path string, numUses int) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host           = "127.0.0.1"
	secret_wo      = "testsecret"
	token_num_uses = %d
`, numUses))
}

func testAccRadiusAuthBackendConfig_tokenPeriod(path string, period int) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host         = "127.0.0.1"
	secret_wo    = "testsecret"
	token_period = %d
`, period))
}

func testAccRadiusAuthBackendConfig_tokenType(path, tokenType string) string {
	return testAccRadiusAuthBackendConfig(path, fmt.Sprintf(`
	host       = "127.0.0.1"
	secret_wo  = "testsecret"
	token_type = "%s"
`, tokenType))
}

func testAccRadiusAuthBackendConfig_multiplePolicies(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                       = "127.0.0.1"
	secret_wo                  = "testsecret"
	unregistered_user_policies = ["default", "readonly", "audit"]
`)
}

func testAccRadiusAuthBackendConfig_withPolicies(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                       = "127.0.0.1"
	secret_wo                  = "testsecret"
	unregistered_user_policies = ["policy1", "policy2"]
`)
}

func testAccRadiusAuthBackendConfig_withoutPolicies(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host      = "127.0.0.1"
	secret_wo = "testsecret"
`)
}

func testAccRadiusAuthBackendConfig_full(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                       = "radius.example.com"
	port                       = 1812
	secret_wo                  = "testsecret"
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
`)
}

func testAccRadiusAuthBackendConfig_aliasMetadata(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host           = "127.0.0.1"
	secret_wo      = "testsecret"
	alias_metadata = {
		foo = "bar"
	}
`)
}

func testAccRadiusAuthBackendConfig_allTokenFields(path string) string {
	return testAccRadiusAuthBackendConfig(path, `
	host                    = "127.0.0.1"
	secret_wo               = "testsecret"
	token_ttl               = 3600
	token_max_ttl           = 7200
	token_policies          = ["policy1", "policy2"]
	token_bound_cidrs       = ["10.0.0.0/8", "192.168.0.0/16"]
	token_no_default_policy = true
	token_num_uses          = 5
	token_period            = 1800
	token_type              = "service"
	alias_metadata = {
		foo = "bar"
	}
`)
}

// TestAccRadiusAuthBackend_namespace tests RADIUS auth backend creation within a namespace.
// This test requires Vault Enterprise as namespaces are an enterprise feature.
func TestAccRadiusAuthBackendConfig_namespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("test-ns")
	path := acctest.RandomWithPrefix("radius-ns")
	resourceName := "vault_radius_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRadiusAuthBackendConfig_namespace(ns, path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "1812"),
				),
			},
			{
				// Set namespace via environment variable for import
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config", path),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldRadiusSecretWO},
			},
			{
				// Clean up the environment variable
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				Config:   testAccRadiusAuthBackendConfig_namespace(ns, path),
				PlanOnly: true,
			},
		},
	})
}

// TestAccRadiusAuthBackend_invalidNamespace tests error handling for non-existent namespace.
// This test requires Vault Enterprise as namespaces are an enterprise feature.
func TestAccRadiusAuthBackendConfig_invalidNamespace(t *testing.T) {
	path := acctest.RandomWithPrefix("radius-invalid-ns")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRadiusAuthBackendConfig_invalidNamespace(path),
				ExpectError: regexp.MustCompile(`no handler for route`),
			},
		},
	})
}

func testAccRadiusAuthBackendConfig_namespace(ns, path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "test" {
	namespace = vault_namespace.test.path
	type      = "radius"
	path      = "%s"
}

resource "vault_radius_auth_backend" "test" {
  namespace = vault_namespace.test.path
	mount     = vault_auth_backend.test.path
  host      = "127.0.0.1"
  secret_wo = "testsecret"
}
`, ns, path)
}

func testAccRadiusAuthBackendConfig_invalidNamespace(path string) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  namespace = "nonexistent-namespace"
	mount     = "%s"
  host      = "127.0.0.1"
  secret_wo = "testsecret"
}
`, path)
}
