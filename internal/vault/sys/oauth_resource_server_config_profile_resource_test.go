// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccOAuthResourceServerConfigProfile_jwks tests JWKS-based profile
func TestAccOAuthResourceServerConfigProfile_jwks(t *testing.T) {
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_jwks(profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerId, "https://example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUseJWKS, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldJWKSURI, "https://example.com/.well-known/jwks.json"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccOAuthResourceServerConfigProfileImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_pem tests PEM-based profile
func TestAccOAuthResourceServerConfigProfile_pem(t *testing.T) {
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	// Generate a test RSA public key
	publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_pem(profileName, publicKeyPEM),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerId, "https://example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUseJWKS, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKeys+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKeys+".0.key_id", "key-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccOAuthResourceServerConfigProfileImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_withAudiences tests profile with audiences
func TestAccOAuthResourceServerConfigProfile_withAudiences(t *testing.T) {
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_withAudiences(profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAudiences+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAudiences+".0", "api.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAudiences+".1", "vault.example.com"),
				),
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_update tests updating profile fields
func TestAccOAuthResourceServerConfigProfile_update(t *testing.T) {
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_jwks(profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserClaim, "sub"),
				),
			},
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_jwksUpdated(profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserClaim, "email"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClockSkewLeeway, "30"),
				),
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_requiresReplace tests fields that require replacement
func TestAccOAuthResourceServerConfigProfile_requiresReplace(t *testing.T) {
	profileName1 := acctest.RandomWithPrefix("test-profile-1")
	profileName2 := acctest.RandomWithPrefix("test-profile-2")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_jwks(profileName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName1),
				),
			},
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_jwks(profileName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName2),
				),
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_namespace tests profile in a namespace
func TestAccOAuthResourceServerConfigProfile_namespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_namespace(ns, profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProfileName, profileName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccOAuthResourceServerConfigProfileNamespaceImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccOAuthResourceServerConfigProfile_algorithms tests custom algorithms
func TestAccOAuthResourceServerConfigProfile_algorithms(t *testing.T) {
	profileName := acctest.RandomWithPrefix("test-profile")
	resourceName := "vault_oauth_resource_server_config_profile.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOAuthResourceServerConfigProfileConfig_algorithms(profileName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedAlgorithms+".0", "RS256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedAlgorithms+".1", "ES256"),
				),
			},
		},
	})
}

// Config helper functions

func testAccOAuthResourceServerConfigProfileConfig_jwks(profileName string) string {
	return fmt.Sprintf(`
resource "vault_oauth_resource_server_config_profile" "test" {
  profile_name = "%s"
  issuer_id    = "https://example.com"
  use_jwks     = true
  jwks_uri     = "https://example.com/.well-known/jwks.json"
}
`, profileName)
}

func testAccOAuthResourceServerConfigProfileConfig_jwksUpdated(profileName string) string {
	return fmt.Sprintf(`
resource "vault_oauth_resource_server_config_profile" "test" {
  profile_name      = "%s"
  issuer_id         = "https://example.com"
  use_jwks          = true
  jwks_uri          = "https://example.com/.well-known/jwks.json"
  enabled           = false
  user_claim        = "email"
  clock_skew_leeway = 30
}
`, profileName)
}

func testAccOAuthResourceServerConfigProfileConfig_pem(profileName, publicKeyPEM string) string {
	return fmt.Sprintf(`
resource "vault_oauth_resource_server_config_profile" "test" {
  profile_name = "%s"
  issuer_id    = "https://example.com"
  use_jwks     = false
  
  public_keys {
    key_id = "key-1"
    pem    = <<-EOT
%s
EOT
  }
}
`, profileName, publicKeyPEM)
}

func testAccOAuthResourceServerConfigProfileConfig_withAudiences(profileName string) string {
	return fmt.Sprintf(`
resource "vault_oauth_resource_server_config_profile" "test" {
  profile_name = "%s"
  issuer_id    = "https://example.com"
  use_jwks     = true
  jwks_uri     = "https://example.com/.well-known/jwks.json"
  audiences    = ["api.example.com", "vault.example.com"]
}
`, profileName)
}

func testAccOAuthResourceServerConfigProfileConfig_namespace(ns, profileName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_oauth_resource_server_config_profile" "test" {
  namespace    = vault_namespace.test.path
  profile_name = "%s"
  issuer_id    = "https://example.com"
  use_jwks     = true
  jwks_uri     = "https://example.com/.well-known/jwks.json"
}
`, ns, profileName)
}

func testAccOAuthResourceServerConfigProfileConfig_algorithms(profileName string) string {
	return fmt.Sprintf(`
resource "vault_oauth_resource_server_config_profile" "test" {
  profile_name          = "%s"
  issuer_id             = "https://example.com"
  use_jwks              = true
  jwks_uri              = "https://example.com/.well-known/jwks.json"
  supported_algorithms  = ["RS256", "ES256"]
}
`, profileName)
}

func testAccOAuthResourceServerConfigProfileImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes[consts.FieldProfileName], nil
	}
}

func testAccOAuthResourceServerConfigProfileNamespaceImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		namespace := rs.Primary.Attributes[consts.FieldNamespace]
		profileName := rs.Primary.Attributes[consts.FieldProfileName]
		return fmt.Sprintf("%s/%s", namespace, profileName), nil
	}
}
