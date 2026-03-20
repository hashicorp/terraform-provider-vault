// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos_test

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
	"github.com/hashicorp/vault/api"
)

const (
	resourceType = "vault_kerberos_auth_backend_ldap_config"
	resourceName = resourceType + ".config"
	testLDAPURL  = "ldap://ldap.example.com"
	testBindDN   = "cn=vault,ou=Users,dc=example,dc=com"
	testUserDN   = "ou=People,dc=example,dc=org"
	testGroupDN  = "ou=Groups,dc=example,dc=org"
	testLDAPSURL = "ldaps://ldap.example.com:636"
)

// TestAccKerberosAuthBackendLDAPConfig_basic tests basic resource creation and import
func TestAccKerberosAuthBackendLDAPConfig_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_basic(path, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDenyNullBind, "true"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config/ldap", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_update tests updating the configuration including token fields and import
func TestAccKerberosAuthBackendLDAPConfig_update(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url1 := "ldap://ldap1.example.com"
	url2 := "ldap://ldap2.example.com"
	bindDN := "cn=vault,ou=Users,dc=example,dc=com"
	userDN := "ou=People,dc=example,dc=org"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_full(path, url1, bindDN, userDN, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url1),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStartTLS, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "false"),
					// Token fields - initial values
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "dev"),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_full(path, url2, bindDN, userDN, true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url2),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStartTLS, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInsecureTLS, "true"),
					// Token fields - updated values
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "dev"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "prod"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPeriod, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "10.0.0.0/8"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "172.16.0.0/12"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config/ldap", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_bindPassUpdate tests updating the bind password
func TestAccKerberosAuthBackendLDAPConfig_bindPassUpdate(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN
	bindPass1 := "password123"
	bindPass2 := "newpassword456"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass1, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "1"),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass2, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "2"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_defaultCheck tests default values
func TestAccKerberosAuthBackendLDAPConfig_defaultCheck(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_defaultValues(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, "kerberos"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, "ldap://127.0.0.1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldBindDN),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldUserDN),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldGroupDN),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCertificate),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldUPNDomain),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldAnonymousGroupSearch),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldUseTokenGroups),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCaseSensitiveNames),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldStartTLS),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldInsecureTLS),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldDiscoverDN),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldUsernameAsAlias),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldMaxPageSize),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldEnableSamaccountnameLogin),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDenyNullBind, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserAttr, "cn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserFilter, "({{.UserAttr}}={{.Username}})"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupFilter, "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupAttr, "cn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSMinVersion, "tls12"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSMaxVersion, "tls12"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRequestTimeout, "90"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDereferenceAliases, "never"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_pathChange tests that changing path requires replacement
func TestAccKerberosAuthBackendLDAPConfig_pathChange(t *testing.T) {
	path1 := acctest.RandomWithPrefix("kerberos")
	path2 := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_basic(path1, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path1),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_basic(path2, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path2),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_validationErrors tests various validation errors
func TestAccKerberosAuthBackendLDAPConfig_validationErrors(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_bindPassWithoutVersion(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`Attribute "bindpass_wo_version" must be specified when "bindpass_wo"`),
			},
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_bindPassVersionWithoutPass(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`Attribute "bindpass_wo" must be specified when "bindpass_wo_version"`),
			},
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_clientCertWithoutVersion(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`Attribute "client_tls_cert_wo_version" must be specified when`),
			},
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_clientKeyWithoutVersion(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`Attribute "client_tls_key_wo_version" must be specified when`),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_runtimeErrors tests runtime errors
func TestAccKerberosAuthBackendLDAPConfig_runtimeErrors(t *testing.T) {
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN
	nonExistentPath := "non-existent-kerberos-backend"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test non-existent backend
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_nonExistentBackend(nonExistentPath, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`error writing|no handler for route|unsupported path`),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_batchTokenWithNumUses tests that batch tokens cannot have limited use count
func TestAccKerberosAuthBackendLDAPConfig_batchTokenWithNumUses(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_batchTokenWithNumUses(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`'token_type' cannot be 'batch' or 'default_batch'`),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_configNotFound tests the config not found scenario
func TestAccKerberosAuthBackendLDAPConfig_configNotFound(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a valid configuration
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_basic(path, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
				),
			},
			// Step 2: Test config not found - resource should be removed from state
			// Delete the config but keep the backend, then try to refresh
			// With the new read() implementation, the resource is automatically removed from state when not found
			{
				PreConfig: func() {
					// Get a Vault client and recreate backend without config
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}
					// Disable the auth backend
					if err := client.Sys().DisableAuth(path); err != nil {
						t.Logf("Warning: failed to disable auth mount: %v", err)
					}
					// Re-enable it without configuration
					if err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
						Type: "kerberos",
					}); err != nil {
						t.Fatalf("failed to enable auth mount: %v", err)
					}
				},
				Config:             testAccKerberosAuthBackendLDAPConfigConfig_basic(path, url, bindDN, userDN),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true, // Expect a plan to recreate the resource since it was removed from state
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_importErrors tests import validation errors
func TestAccKerberosAuthBackendLDAPConfig_importErrors(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test completely invalid import ID
			{
				Config:            testAccKerberosAuthBackendLDAPConfigConfig_basic("test", testLDAPURL, testBindDN, testUserDN),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "invalid-import-id",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID missing /config/ldap suffix
			{
				Config:            testAccKerberosAuthBackendLDAPConfigConfig_basic("test", testLDAPURL, testBindDN, testUserDN),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "auth/kerberos",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID missing auth/ prefix
			{
				Config:            testAccKerberosAuthBackendLDAPConfigConfig_basic("test", testLDAPURL, testBindDN, testUserDN),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "kerberos/config/ldap",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
			// Test import ID with empty path between prefix and suffix
			{
				Config:            testAccKerberosAuthBackendLDAPConfigConfig_basic("test", testLDAPURL, testBindDN, testUserDN),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "auth//config/ldap",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid import ID format`),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_allFields tests configuration with all fields
func TestAccKerberosAuthBackendLDAPConfig_allFields(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPSURL
	bindDN := testBindDN
	userDN := testUserDN
	groupDN := testGroupDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_allFields(path, url, bindDN, userDN, groupDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserDN, userDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupDN, groupDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserAttr, "samaccountname"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUserFilter, "(objectClass=person)"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupAttr, "cn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupFilter, "(objectClass=group)"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAnonymousGroupSearch, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUseTokenGroups, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCaseSensitiveNames, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSMinVersion, "tls12"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSMaxVersion, "tls13"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCertificate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientTLSCertWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientTLSKeyWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDenyNullBind, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDiscoverDN, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUPNDomain, "example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRequestTimeout, "90"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionTimeout, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameAsAlias, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDereferenceAliases, "never"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxPageSize, "1000"),
					// Token fields
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "dev"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenPolicies+".*", "prod"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenBoundCIDRs+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "10.0.0.0/8"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenBoundCIDRs+".*", "172.16.0.0/12"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenExplicitMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNoDefaultPolicy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenNumUses, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenPeriod, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenType, "service"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_aliasMetadata tests alias_metadata configuration (Vault 1.21.0+)
func TestAccKerberosAuthBackendLDAPConfig_aliasMetadata(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_aliasMetadata(path, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".department", "engineering"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".location", "us-west"),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_aliasMetadataUpdated(path, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".%", "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".department", "security"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".location", "us-east"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAliasMetadata+".team", "platform"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_enableSAMAccountNameLogin tests enable_samaccountname_login configuration (Vault 1.19.0+)
func TestAccKerberosAuthBackendLDAPConfig_enableSAMAccountNameLogin(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion119)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_enableSAMAccountNameLogin(path, url, bindDN, userDN, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableSamaccountnameLogin, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUPNDomain, "example.com"),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_enableSAMAccountNameLogin(path, url, bindDN, userDN, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableSamaccountnameLogin, "false"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_namespace tests configuration with namespace (Enterprise only)
func TestAccKerberosAuthBackendLDAPConfig_namespace(t *testing.T) {
	namespace := acctest.RandomWithPrefix("tf-ns")
	path := acctest.RandomWithPrefix("kerberos")
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_namespace(namespace, path, url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
				),
			},
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/config/ldap", path),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
			{
				// Cleanup step needed for the import step above
				Config: testAccKerberosAuthBackendLDAPConfigConfig_namespace(namespace, path, url, bindDN, userDN),
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				PlanOnly: true,
			},
			{
				Config:      testAccKerberosAuthBackendLDAPConfigConfig_invalidNamespace(path, url, bindDN, userDN),
				ExpectError: regexp.MustCompile(`no handler for route|route entry not found`),
			},
		},
	})
}

// Configuration templates for negative tests

func testAccKerberosAuthBackendLDAPConfigConfig_bindPassWithoutVersion(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount       = vault_auth_backend.kerberos.path
  url         = %q
  binddn      = %q
  bindpass_wo = "password123"
  userdn      = %q
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_bindPassVersionWithoutPass(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount                = vault_auth_backend.kerberos.path
  url                  = %q
  binddn               = %q
  bindpass_wo_version  = 1
  userdn               = %q
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_clientCertWithoutVersion(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount              = vault_auth_backend.kerberos.path
  url                = %q
  binddn             = %q
  userdn             = %q
  client_tls_cert_wo = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_clientKeyWithoutVersion(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount             = vault_auth_backend.kerberos.path
  url               = %q
  binddn            = %q
  userdn            = %q
  client_tls_key_wo = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_nonExistentBackend(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount  = %q
  url    = %q
  binddn = %q
  userdn = %q
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_batchTokenWithNumUses(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount          = vault_auth_backend.kerberos.path
  url            = %q
  binddn         = %q
  userdn         = %q
  token_type     = "batch"
  token_num_uses = 10
}
`, path, url, bindDN, userDN)
}

// Configuration templates for positive tests

func testAccKerberosAuthBackendLDAPConfigConfig_basic(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount  = vault_auth_backend.kerberos.path
  url    = %q
  binddn = %q
  userdn = %q
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_full(path, url, bindDN, userDN string, startTLS, insecureTLS bool) string {
	config := fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount        = vault_auth_backend.kerberos.path
  url          = %q
  binddn       = %q
  userdn       = %q
  starttls     = %t
  insecure_tls = %t
`, path, url, bindDN, userDN, startTLS, insecureTLS)

	// Add token fields based on configuration
	if startTLS {
		// Updated token configuration
		// Note: token_type must be "service" when token_num_uses is set (Vault constraint)
		config += `
	 token_ttl              = 3600
	 token_max_ttl          = 7200
	 token_policies         = ["default", "dev", "prod"]
	 token_bound_cidrs      = ["10.0.0.0/8", "172.16.0.0/12"]
	 token_no_default_policy = true
	 token_num_uses         = 10
	 token_period           = 86400
	 token_type             = "service"
`
	} else {
		// Initial token configuration
		config += `
  token_ttl      = 1800
  token_max_ttl  = 3600
  token_policies = ["default", "dev"]
  token_type     = "service"
`
	}

	config += "}\n"
	return config
}

func testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  url                 = %q
  binddn              = %q
  userdn              = %q
  bindpass_wo         = %q
  bindpass_wo_version = %d
}
`, path, url, bindDN, userDN, bindPass, version)
}

func testAccKerberosAuthBackendLDAPConfigConfig_defaultValues() string {
	return `
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount = vault_auth_backend.kerberos.path
}
`
}

func testAccKerberosAuthBackendLDAPConfigConfig_namespace(namespace, path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.test.path
  type      = "kerberos"
  path      = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.kerberos.path
  url       = %q
  binddn    = %q
  userdn    = %q
}
`, namespace, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_invalidNamespace(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  namespace = "nonexistent-namespace"
  mount     = vault_auth_backend.kerberos.path
  url       = %q
  binddn    = %q
  userdn    = %q
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_allFields(path, url, bindDN, userDN, groupDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount                        = vault_auth_backend.kerberos.path
  url                          = %q
  binddn                       = %q
  userdn                       = %q
  groupdn                      = %q
  userattr                     = "samaccountname"
  userfilter                   = "(objectClass=person)"
  groupattr                    = "cn"
  groupfilter                  = "(objectClass=group)"
  anonymous_group_search       = true
  use_token_groups             = true
  case_sensitive_names         = false
  tls_min_version              = "tls12"
  tls_max_version              = "tls13"
  certificate               = <<-EOT
-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUT8HWtkylgRpf0/aXMt0Fufrc+PQwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMTMxMjQ4NTFa
Fw0zNjAzMTAxMjQ4NTFaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpbw4YjPqeMFuvkVhhO6qdWRHV
bmb+5RCSJTiISt1hDF7Ojm9p0w+NBflM1GhrjefhdEcNUWyHBJD2pAp7bNzL5urB
ks+YzA9rSYBiDZKqRKG4tgND1Db12Innn3XB+3iliTcn5W1+Aur0QgbIQyfRWYix
G6ktu3FRW85ZU/91pfrvKqmIKxP+RlocT7jU8MlyPnYmCLG3VjB+eIg0QLAjLn58
BUyLuVcnO4ZA2I8gk4w2U3pdyTEM1rGAEniYEvPvOTdNQqQv57AJ1ehJJPVJ2px3
sGCx8bTFao1v3UqqR2AjDY4/hevRw3CBgVnXE+PNpHtqDsS4XmvLicYx2APZAgMB
AAGjUzBRMB0GA1UdDgQWBBTOPBH+IQh1oG5ai0jLBhJDuqwntTAfBgNVHSMEGDAW
gBTOPBH+IQh1oG5ai0jLBhJDuqwntTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCn8xasToI7y/95zvONoHa0JGbSJitn7eSBthBu7C5AV2x6CZqH
NZJEHsR7NKfmx8d3wIh0sGoMlOgqiy7bG/Pj/cYZeZhn57M8Cj8KUP5vy2EuA/f4
Q5Wpc2sFbRa8wO+pDa13hIQzvPnAcOfwLdjgnMd80miL9nDYeAdW7nK/EZA94Aoa
R4JwIF4hNBF3C7ZZ4R9gd70ZX3qcy7IjXvTmnOLUlvd6HnTI42Jmq80NFkyVOg/3
ZscqCwaiRiHHPi/TnX0RlpXBJgvwmMTh5FS/iUkYBUwFgRz0IkNPAC6aen2KyPWk
S095THILQpinS1k7aEMGfl2seEOmnI4Ou/nT
-----END CERTIFICATE-----
EOT
  client_tls_cert_wo        = <<-EOT
-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUT8HWtkylgRpf0/aXMt0Fufrc+PQwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMTMxMjQ4NTFa
Fw0zNjAzMTAxMjQ4NTFaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpbw4YjPqeMFuvkVhhO6qdWRHV
bmb+5RCSJTiISt1hDF7Ojm9p0w+NBflM1GhrjefhdEcNUWyHBJD2pAp7bNzL5urB
ks+YzA9rSYBiDZKqRKG4tgND1Db12Innn3XB+3iliTcn5W1+Aur0QgbIQyfRWYix
G6ktu3FRW85ZU/91pfrvKqmIKxP+RlocT7jU8MlyPnYmCLG3VjB+eIg0QLAjLn58
BUyLuVcnO4ZA2I8gk4w2U3pdyTEM1rGAEniYEvPvOTdNQqQv57AJ1ehJJPVJ2px3
sGCx8bTFao1v3UqqR2AjDY4/hevRw3CBgVnXE+PNpHtqDsS4XmvLicYx2APZAgMB
AAGjUzBRMB0GA1UdDgQWBBTOPBH+IQh1oG5ai0jLBhJDuqwntTAfBgNVHSMEGDAW
gBTOPBH+IQh1oG5ai0jLBhJDuqwntTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCn8xasToI7y/95zvONoHa0JGbSJitn7eSBthBu7C5AV2x6CZqH
NZJEHsR7NKfmx8d3wIh0sGoMlOgqiy7bG/Pj/cYZeZhn57M8Cj8KUP5vy2EuA/f4
Q5Wpc2sFbRa8wO+pDa13hIQzvPnAcOfwLdjgnMd80miL9nDYeAdW7nK/EZA94Aoa
R4JwIF4hNBF3C7ZZ4R9gd70ZX3qcy7IjXvTmnOLUlvd6HnTI42Jmq80NFkyVOg/3
ZscqCwaiRiHHPi/TnX0RlpXBJgvwmMTh5FS/iUkYBUwFgRz0IkNPAC6aen2KyPWk
S095THILQpinS1k7aEMGfl2seEOmnI4Ou/nT
-----END CERTIFICATE-----
EOT
  client_tls_cert_wo_version = 1
  client_tls_key_wo         = <<-EOT
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpbw4YjPqeMFuv
kVhhO6qdWRHVbmb+5RCSJTiISt1hDF7Ojm9p0w+NBflM1GhrjefhdEcNUWyHBJD2
pAp7bNzL5urBks+YzA9rSYBiDZKqRKG4tgND1Db12Innn3XB+3iliTcn5W1+Aur0
QgbIQyfRWYixG6ktu3FRW85ZU/91pfrvKqmIKxP+RlocT7jU8MlyPnYmCLG3VjB+
eIg0QLAjLn58BUyLuVcnO4ZA2I8gk4w2U3pdyTEM1rGAEniYEvPvOTdNQqQv57AJ
1ehJJPVJ2px3sGCx8bTFao1v3UqqR2AjDY4/hevRw3CBgVnXE+PNpHtqDsS4XmvL
icYx2APZAgMBAAECggEABL4cX7RRjTA3VKhTztnq+/poydjN3+Tggs+dx+sZd1TM
gk7Thadjm/5gk8aG/pRp/yMhJGygk1es6E3p5psOG1hsMZWdgSG4OHpMUPGspqfx
TzLnexPPMAx/tMSBHHlS+K4CgF2BbXt6sY6724q9vtueUtbYh5TU1w3R8e+qc4Xr
VBLucSh6L3T+Q4FFnGUUhAMlVpUdLK2V2GH/62nsWv9V0yp4ATsgFPwL59i17nyg
TrJ1Uys7sOJeJjJamhgpmhOWjkOFpr5z9o0G/2RQyrPsbMOuu9Rnt+AJRWcy8Hh8
8FreWfHV6wnaIe/SXBbiG+1o8Aci7SF6c0B2OzVLXwKBgQD9qPwdYrh82Zlcfx2r
6KXHYfraY/5sNnz9y6i8wicnB6y+1S+w/q9fnfMJQ9iX4Dw/BYmTj2fjSwTnzwRy
0mD3uBkpMafasC7wtY5MBYnQLEpvhIhPpo5zdyllAKvE4CmzfViSFT7F65tgOP04
a/VcU+jnYobYhGaHOD7juoPqIwKBgQDrlk5dN3CaCjR+n7AnU8pmgP7/sQivGK/z
7ieykGleodzqhsQUKI5H4bM3UCHAOcr89EU8JaguG2dEWAkolQBkLzSytvB1CzB8
/0z8BvuHvlnWGzkVFGW+zOhmWupRpzvglr9T36S2BoBHsiyX3tDQ9Ph0s8kb7egD
92IORQvj0wKBgQCt/XBZU7LJ6JP6TzLyDNVRitJ/ZGFKpqFbkIuAVgh3DBugliht
VnTCuFvROhliK6wHamvwrEgNLxMBUg1yGP3sTPntOKMzLPA1qcMeQBpEkWzJS3YY
dF13s//PyQMJOt0/wbW0FiCFr9NW0CBYyCx3lRLHS9zEvSR6kckJeZEsUwKBgQCo
5AVj8GXKGLzPdh2r4/b7C0lD9x+Zn2IsxrQw4DSaAgJFI74YEYcG4zg+1DSOASCT
vW6RExIBk+WxakeOj1tLd0gZQusZjZ8CTWhcWYkjJIR06OlAQnI6md2V22GWjgRw
GsIpF/CWCg0W2RX8/mDHHIet6mGnoyOtDEGAp2FBvwKBgADwYaLgvpxwZFBq3d8e
8nvcfCi3UqIyXlm6CRkZhtOGvhS0pZzJocWQdSkcWaITRWcrbb5I9UAkWCRCp8P3
NF8CWGLZpxhdm75eXy0RdPKy2h+Xp3fIi6hAdoOR8z1KiTs7swRh9dS4jcbNYxzO
H6Kj7Yv/nKr9jdhDJ1iMUjse
-----END PRIVATE KEY-----
EOT
  client_tls_key_wo_version    = 1
  deny_null_bind               = true
  discoverdn                  = true
  upndomain                    = "example.com"
  request_timeout              = 90
  connection_timeout           = 30
  username_as_alias            = true
  dereference_aliases          = "never"
  max_page_size                = 1000
  
  # Token fields
  token_ttl                 = 1800
  token_max_ttl             = 3600
  token_policies            = ["default", "dev", "prod"]
  token_bound_cidrs         = ["10.0.0.0/8", "172.16.0.0/12"]
  token_explicit_max_ttl    = 7200
  token_no_default_policy   = true
  token_num_uses            = 10
  token_period              = 86400
  token_type                = "service"
}
`, path, url, bindDN, userDN, groupDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_aliasMetadata(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount  = vault_auth_backend.kerberos.path
  url    = %q
  binddn = %q
  userdn = %q
  
  alias_metadata = {
    department = "engineering"
    location   = "us-west"
  }
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_aliasMetadataUpdated(path, url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount  = vault_auth_backend.kerberos.path
  url    = %q
  binddn = %q
  userdn = %q
  
  alias_metadata = {
    department = "security"
    location   = "us-east"
    team       = "platform"
  }
}
`, path, url, bindDN, userDN)
}

func testAccKerberosAuthBackendLDAPConfigConfig_enableSAMAccountNameLogin(path, url, bindDN, userDN string, enabled bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount                       = vault_auth_backend.kerberos.path
  url                         = %q
  binddn                      = %q
  userdn                      = %q
  upndomain                   = "example.com"
  enable_samaccountname_login = %t
}
`, path, url, bindDN, userDN, enabled)
}
