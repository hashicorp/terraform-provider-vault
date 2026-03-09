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

// TestAccKerberosAuthBackendLDAPConfig_basic tests basic resource creation
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
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_update tests updating the configuration including token fields
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
				Config: testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass1, "v1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "v1"),
				),
			},
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass2, "v2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindDN, bindDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "v2"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_import tests importing the resource
func TestAccKerberosAuthBackendLDAPConfig_import(t *testing.T) {
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

// TestAccKerberosAuthBackendLDAPConfig_defaultCheck tests default values
func TestAccKerberosAuthBackendLDAPConfig_defaultCheck(t *testing.T) {
	url := testLDAPURL
	bindDN := testBindDN
	userDN := testUserDN

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLDAPConfigConfig_defaultValues(url, bindDN, userDN),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, "kerberos"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldURL, url),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientTLSCertWOVersion, "v1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientTLSKeyWOVersion, "v1"),
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
		},
	})
}

// TestAccKerberosAuthBackendLDAPConfig_importWithNamespace tests importing with namespace (Enterprise only)
func TestAccKerberosAuthBackendLDAPConfig_importWithNamespace(t *testing.T) {
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
  bindpass_wo_version  = "v1"
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

func testAccKerberosAuthBackendLDAPConfigConfig_withBindPass(path, url, bindDN, userDN, bindPass, version string) string {
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
  bindpass_wo_version = %q
}
`, path, url, bindDN, userDN, bindPass, version)
}

func testAccKerberosAuthBackendLDAPConfigConfig_defaultValues(url, bindDN, userDN string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  url        = %q
  binddn     = %q
  userdn     = %q
  depends_on = [vault_auth_backend.kerberos]
}
`, url, bindDN, userDN)
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
MIIFFzCCAv+gAwIBAgIUcAlkyVCITwjNN1V2KtxlGp5jYKkwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMDIwOTA4NTVa
Fw0zNjAyMjgwOTA4NTVaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDEgahnOJmjd1ncFm+Za+OiPr9R
bPbsKFthpsLbT/AFptEUi2PqfjL444o5EbFiNxxTKA8Dw5ddKD4mr3ijeAK2WkW2
7XEpA48G+fKAtMipm8aX19s2gLj/W4L1evAkcpDO9xm+1rtoD1FP+BbWzlAdGRhz
7B8aVyR72V5lyXOG2MC4xM1ClQ1PKeeGMZhcAyLANDaz1mEVAD/zjYAabQEdxq8B
7mWbM+p7uWqWzIGb0MFwxc8mdCwkeqMBxfUQRqkKhzo13glD2eJZ9m1A5E7cdg8B
G3g5uhB7s5vtZYau7OH+PFqnzbSm8umjX13e+NkU9lFPcuJPyS1A/aBjZCyjdPSR
WrVQhzAOZL8zxHG+faUEdh4Q2AlEc4XlOPO6dlgpAQAhbX5BnpK3bFXOHo1LpxLG
tWEevTU5xnK0SBg6k+JZbp7kwPUI0g7AT6vheQje5+h0pdV0VTdirBcSO0sAFoMJ
swAPTBMZD2038cVsrrfN/oDwc1f9byZZmRW0uC5vSQGczkHHULPu9lqt53VgZ/1J
SHqqN/ykCWZv4EU6OKkEe7uFUWbPbFfSIAib8B4wsuAdIYQNdA52PmVMBuQhNzEF
VP+X4P4wiENPlP5QdCahxyqZRX1A8WGFy1Nb1cPwShk/jx37WIA3xajSEYWWCOzL
TkmodiIxRm1NfKNeHwIDAQABo1MwUTAdBgNVHQ4EFgQU6/e/Sa74i2omJuS0zrQ+
UrhHi3YwHwYDVR0jBBgwFoAU6/e/Sa74i2omJuS0zrQ+UrhHi3YwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAi1J47qC6ViH2XdycVzcdIOeBbum9
mNa30VveE3nxEFUCaMzpUHc+KZcBNYBbeEORT5TF/cs5VnVpOPqnMi1aXdo8oD9t
M4fpFaxETep1+fkVGMJW+AexW4CGfsO5VoyoB9fZcbOMdNc95Hn8zgibxRSlEIpB
4leFW1E8vk1RmzyZYqVxmj6kTvtQA9Fzr+M3Mxb6xRNs2xgvGV2pQCqxLYnzJGVN
+zWPuISAUeG+/vk4l1NmzwPSPmZGAG7ZU1n8yAgBBB04sjextyw4cMRv7OXhy9Qq
KF5j4xDMgjZfBJz9Vy7nIk0mDM6ATlpg6qFTlLyFrr7gO5EHThwmvVS3f7svlZZW
pu2e/EeCYRfSwre71Nqrl+6C7qwwkjolU/9L2kmzdYlHfxitaPqPkO1NwUhLVEnt
xxvKU9ze22szwQJ5F/CIAtUr0jsWoMO2rGxb3HwGv0Ui6OoPWwP8RWY8L6VBMTr+
/3IYTIXwyKOZ1PY6cTWkpeJEhjqzhiSFUJmAe7BUoIlacLNipKqJvUhSVHaubXFU
bHcwCZQnipclG+DpaGmoyxHuX2KWUjUxaBT0Rn3GVM+4t8fi5j9uZ09TtLR6Bsd5
BxyDvzDQC8BSvaYaAdC4xg+smeJXqIh/xEPAlBLsvVO1nGLJCP0/OVCnacN7Fhd2
4YlTTTMEjZLGUaQ=
-----END CERTIFICATE-----
EOT
  client_tls_cert_wo        = <<-EOT
-----BEGIN CERTIFICATE-----
MIIFFzCCAv+gAwIBAgIUcAlkyVCITwjNN1V2KtxlGp5jYKkwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMDIwOTA4NTVa
Fw0zNjAyMjgwOTA4NTVaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDEgahnOJmjd1ncFm+Za+OiPr9R
bPbsKFthpsLbT/AFptEUi2PqfjL444o5EbFiNxxTKA8Dw5ddKD4mr3ijeAK2WkW2
7XEpA48G+fKAtMipm8aX19s2gLj/W4L1evAkcpDO9xm+1rtoD1FP+BbWzlAdGRhz
7B8aVyR72V5lyXOG2MC4xM1ClQ1PKeeGMZhcAyLANDaz1mEVAD/zjYAabQEdxq8B
7mWbM+p7uWqWzIGb0MFwxc8mdCwkeqMBxfUQRqkKhzo13glD2eJZ9m1A5E7cdg8B
G3g5uhB7s5vtZYau7OH+PFqnzbSm8umjX13e+NkU9lFPcuJPyS1A/aBjZCyjdPSR
WrVQhzAOZL8zxHG+faUEdh4Q2AlEc4XlOPO6dlgpAQAhbX5BnpK3bFXOHo1LpxLG
tWEevTU5xnK0SBg6k+JZbp7kwPUI0g7AT6vheQje5+h0pdV0VTdirBcSO0sAFoMJ
swAPTBMZD2038cVsrrfN/oDwc1f9byZZmRW0uC5vSQGczkHHULPu9lqt53VgZ/1J
SHqqN/ykCWZv4EU6OKkEe7uFUWbPbFfSIAib8B4wsuAdIYQNdA52PmVMBuQhNzEF
VP+X4P4wiENPlP5QdCahxyqZRX1A8WGFy1Nb1cPwShk/jx37WIA3xajSEYWWCOzL
TkmodiIxRm1NfKNeHwIDAQABo1MwUTAdBgNVHQ4EFgQU6/e/Sa74i2omJuS0zrQ+
UrhHi3YwHwYDVR0jBBgwFoAU6/e/Sa74i2omJuS0zrQ+UrhHi3YwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAi1J47qC6ViH2XdycVzcdIOeBbum9
mNa30VveE3nxEFUCaMzpUHc+KZcBNYBbeEORT5TF/cs5VnVpOPqnMi1aXdo8oD9t
M4fpFaxETep1+fkVGMJW+AexW4CGfsO5VoyoB9fZcbOMdNc95Hn8zgibxRSlEIpB
4leFW1E8vk1RmzyZYqVxmj6kTvtQA9Fzr+M3Mxb6xRNs2xgvGV2pQCqxLYnzJGVN
+zWPuISAUeG+/vk4l1NmzwPSPmZGAG7ZU1n8yAgBBB04sjextyw4cMRv7OXhy9Qq
KF5j4xDMgjZfBJz9Vy7nIk0mDM6ATlpg6qFTlLyFrr7gO5EHThwmvVS3f7svlZZW
pu2e/EeCYRfSwre71Nqrl+6C7qwwkjolU/9L2kmzdYlHfxitaPqPkO1NwUhLVEnt
xxvKU9ze22szwQJ5F/CIAtUr0jsWoMO2rGxb3HwGv0Ui6OoPWwP8RWY8L6VBMTr+
/3IYTIXwyKOZ1PY6cTWkpeJEhjqzhiSFUJmAe7BUoIlacLNipKqJvUhSVHaubXFU
bHcwCZQnipclG+DpaGmoyxHuX2KWUjUxaBT0Rn3GVM+4t8fi5j9uZ09TtLR6Bsd5
BxyDvzDQC8BSvaYaAdC4xg+smeJXqIh/xEPAlBLsvVO1nGLJCP0/OVCnacN7Fhd2
4YlTTTMEjZLGUaQ=
-----END CERTIFICATE-----
EOT
  client_tls_cert_wo_version = "v1"
  client_tls_key_wo         = <<-EOT
-----BEGIN PRIVATE KEY-----
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
Ho+YcALanw2+6W3RQ846IdJPRkkEOtM=
-----END PRIVATE KEY-----
EOT
  client_tls_key_wo_version    = "v1"
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
