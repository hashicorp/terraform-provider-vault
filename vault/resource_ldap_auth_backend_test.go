// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/vault/api"
)

func TestLDAPAuthBackend_basic(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-ldap-path")

	resourceName := "vault_ldap_auth_backend.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendDestroy,

		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true", "true", ""),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "false", "true", ""),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true", "false", ""),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "false", "false", ""),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true", "false", ""),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_defaults(path),
				Check: func(s *terraform.State) error {
					checks := []resource.TestCheckFunc{
						testLDAPAuthBackendCheck_attrs(resourceName, path),
						// Verify computed defaults - these fields should be set by Vault if not specified
						resource.TestCheckResourceAttr(resourceName, "request_timeout", "90"),
						resource.TestCheckResourceAttr(resourceName, "dereference_aliases", "never"),
						resource.TestCheckResourceAttr(resourceName, "anonymous_group_search", "false"),
					}

					// Only check enable_samaccountname_login if Vault >= 1.19
					if provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion119) {
						checks = append(checks, resource.TestCheckResourceAttr(resourceName, "enable_samaccountname_login", "false"))
					}

					return resource.ComposeTestCheckFunc(checks...)(s)
				},
			},
			{
				Config:      testLDAPAuthBackendConfig_params(path, -20, "never", true, true),
				ExpectError: regexp.MustCompile("cannot provide negative value"),
			},
			{
				Config: testLDAPAuthBackendConfig_params(path, 20, "always", false, false),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_params(path, 45, "finding", false, true),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_params(path, 45, "always", true, false),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsAPISupported(provider.VaultVersion121) {
						return true, nil
					}

					return !meta.IsEnterpriseSupported(), nil
				},
				Config: testLDAPAuthBackendConfig_basic(path, "true", "true", aliasMetadataConfig),
				Check: resource.ComposeTestCheckFunc(
					testLDAPAuthBackendCheck_attrs(resourceName, path),
					resource.TestCheckResourceAttr(resourceName, "alias_metadata.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "alias_metadata.foo", "bar"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "disable_remount", "enable_samaccountname_login"),
		},
	})
}

func TestLDAPAuthBackend_tls(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-ldap-tls-path")

	resourceName := "vault_ldap_auth_backend.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendDestroy,

		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_tls(path, "true", "true"),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "false", "true"),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "true", "false"),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "false", "false"),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			{
				Config: testLDAPAuthBackendConfig_tls(path, "true", "false"),
				Check:  testLDAPAuthBackendCheck_attrs(resourceName, path),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass",
				"client_tls_cert", "client_tls_key", "disable_remount", "enable_samaccountname_login"),
		},
	})
}

func TestLDAPAuthBackend_remount(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-ldap")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-ldap-updated")

	resourceName := "vault_ldap_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_basic(path, "true", "true", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					testLDAPAuthBackendCheck_attrs(resourceName, path),
				),
			},
			{
				Config: testLDAPAuthBackendConfig_basic(updatedPath, "true", "true", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					testLDAPAuthBackendCheck_attrs(resourceName, updatedPath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "disable_remount", "enable_samaccountname_login"),
		},
	})
}

func TestLDAPAuthBackend_automatedRotation(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-ldap")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-ldap-updated")

	resourceName := "vault_ldap_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_automatedRotation(path, true, true, "* * * * *", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					testLDAPAuthBackendCheck_attrs(resourceName, path),
				),
			},
			{
				Config: testLDAPAuthBackendConfig_automatedRotation(updatedPath, true, true, "", 0, 10, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					testLDAPAuthBackendCheck_attrs(resourceName, updatedPath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldBindPass, consts.FieldDisableRemount),
		},
	})
}

func TestLDAPAuthBackend_bindpassWO(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-ldap-bindpass-wo")

	resourceName := "vault_ldap_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_bindpassWO(path, "supersecurepassword", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "1"),
				),
			},
			{
				Config: testLDAPAuthBackendConfig_bindpassWO(path, "updatedsecurepassword", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBindPassWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldBindPassWO,
				consts.FieldBindPassWOVersion,
				consts.FieldDisableRemount,
			),
		},
	})
}

func TestLDAPAuthBackend_bindpassConflict(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("tf-test-ldap-bindpass-conflict")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testLDAPAuthBackendConfig_bindpassConflict(path),
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
				Destroy:     false,
			},
		},
	})
}

func TestLDAPAuthBackend_tuning(t *testing.T) {
	t.Parallel()
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-ldap-tune-")
	resourceName := "vault_ldap_auth_backend.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackend_tune_partial(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
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
				Config: testLDAPAuthBackend_tune_full(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
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

func TestLDAPAuthBackend_importTune(t *testing.T) {
	t.Parallel()
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-ldap-import-tune-")
	resourceName := "vault_ldap_auth_backend.test"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackend_tune_full(path),
				Check: testutil.TestAccCheckAuthMountExists(resourceName,
					&resAuth,
					testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldBindPass, consts.FieldDisableRemount),
		},
	})
}

func TestLDAPAuthBackend_tune_conflicts(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("ldap")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
				resource "vault_ldap_auth_backend" "test" {
					path = "%s"
					url = "ldap://127.0.0.1"
					userdn = "ou=Users,dc=example,dc=com"
					userattr = "uid"
					groupdn = "ou=Groups,dc=example,dc=com"
					groupfilter = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
					groupattr = "cn"
					insecure_tls = true
					token_ttl = 3600
					tune {
						default_lease_ttl = "10m"
					}
				}
				`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
			{
				Config: fmt.Sprintf(`
				resource "vault_ldap_auth_backend" "test" {
					path = "%s"
					url = "ldap://127.0.0.1"
					userdn = "ou=Users,dc=example,dc=com"
					userattr = "uid"
					groupdn = "ou=Groups,dc=example,dc=com"
					groupfilter = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
					groupattr = "cn"
					insecure_tls = true
					token_max_ttl = 3600
					tune {
						max_lease_ttl = "20m"
					}
				}
				`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
			{
				Config: fmt.Sprintf(`
				resource "vault_ldap_auth_backend" "test" {
					path = "%s"
					url = "ldap://127.0.0.1"
					userdn = "ou=Users,dc=example,dc=com"
					userattr = "uid"
					groupdn = "ou=Groups,dc=example,dc=com"
					groupfilter = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
					groupattr = "cn"
					insecure_tls = true
					token_type = "batch"
					tune {
						token_type = "service"
					}
				}
				`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
		},
	})
}

func TestLDAPAuthBackend_denyNullBindDefault(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-ldap-deny-null-bind")

	resourceName := "vault_ldap_auth_backend.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfig_denyNullBindNotSet(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					// Verify deny_null_bind defaults to true when not explicitly set
					resource.TestCheckResourceAttr(resourceName, "deny_null_bind", "true"),
					testLDAPAuthBackendCheck_attrs(resourceName, path),
				),
			},
			{
				Config: testLDAPAuthBackendConfig_denyNullBindExplicitFalse(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					// Verify deny_null_bind can be explicitly set to false
					resource.TestCheckResourceAttr(resourceName, "deny_null_bind", "false"),
					testLDAPAuthBackendCheck_attrs(resourceName, path),
				),
			},
			{
				Config: testLDAPAuthBackendConfig_denyNullBindNotSet(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					// Verify deny_null_bind returns to default true when removed from config
					resource.TestCheckResourceAttr(resourceName, "deny_null_bind", "true"),
					testLDAPAuthBackendCheck_attrs(resourceName, path),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "disable_remount"),
		},
	})
}

func testLDAPAuthBackendDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendCheck_attrs(resourceName string, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		endpoint := strings.Trim(name, "/")
		if endpoint != path {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, path)
		}

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(name, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", name)
		}

		if "ldap" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		if rs.Primary.Attributes["accessor"] != authMount.Accessor {
			return fmt.Errorf("accessor in state %s does not match accessor returned from vault %s",
				rs.Primary.Attributes["accessor"],
				authMount.Accessor)
		}

		l := rs.Primary.Attributes["local"] == "true"
		if l != authMount.Local {
			return fmt.Errorf("local bool in state for %s does not match value returned from vault: State: %t, Vault: %t",
				name, l, authMount.Local)
		}

		configPath := "auth/" + endpoint + "/config"

		resp, err := client.Logical().Read(configPath)
		if err != nil {
			return err
		}

		// TODO: this does not belong here, should be done a !TestCheckAttrSet...
		// Check that `bindpass`, if present in the state, is not returned by the API
		if rs.Primary.Attributes["bindpass"] != "" && resp.Data["bindpass"] != nil {
			return fmt.Errorf("expected api field bindpass to not be returned, but was %q", resp.Data["bindpass"])
		}

		// TODO: this does not belong here, should be done a !TestCheckAttrSet...
		// Check that `client_tls_crt`, if present in the state, is not returned by the API
		if rs.Primary.Attributes["client_tls_crt"] != "" && resp.Data["client_tls_crt"] != nil {
			return fmt.Errorf("expected api field client_tls_crt to not be returned, but was %q", resp.Data["client_tls_crt"])
		}

		// TODO: this does not belong here, should be done a !TestCheckAttrSet... ,
		// the part should be handled in vault tests.
		// Check that `client_tls_key`, if present in the state, is not returned by the API
		if rs.Primary.Attributes["client_tls_key"] != "" && resp.Data["client_tls_key"] != nil {
			return fmt.Errorf("expected api field client_tls_key to not be returned, but was %q", resp.Data["client_tls_key"])
		}

		attrs := map[string]string{
			"url":                    "url",
			"starttls":               "starttls",
			"case_sensitive_names":   "case_sensitive_names",
			"tls_min_version":        "tls_min_version",
			"tls_max_version":        "tls_max_version",
			"insecure_tls":           "insecure_tls",
			"certificate":            "certificate",
			"binddn":                 "binddn",
			"userdn":                 "userdn",
			"userattr":               "userattr",
			"userfilter":             "userfilter",
			"discoverdn":             "discoverdn",
			"deny_null_bind":         "deny_null_bind",
			"upndomain":              "upndomain",
			"groupfilter":            "groupfilter",
			"username_as_alias":      "username_as_alias",
			"groupdn":                "groupdn",
			"groupattr":              "groupattr",
			"use_token_groups":       "use_token_groups",
			"connection_timeout":     "connection_timeout",
			"request_timeout":        "request_timeout",
			"dereference_aliases":    "dereference_aliases",
			"anonymous_group_search": "anonymous_group_search",
		}

		isVaultVersion111 := provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion111)
		if isVaultVersion111 {
			attrs["max_page_size"] = "max_page_size"
		}

		isVaultVersion119 := provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion119)
		if isVaultVersion119 {
			attrs["enable_samaccountname_login"] = "enable_samaccountname_login"
		}

		if provider.IsEnterpriseSupported(testProvider.Meta()) && provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion119) {
			attrs["rotation_schedule"] = "rotation_schedule"
			attrs["rotation_window"] = "rotation_window"
			attrs["rotation_period"] = "rotation_period"
			attrs["disable_automated_rotation"] = "disable_automated_rotation"
		}

		for _, v := range commonTokenFields {
			attrs[v] = v
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}
			switch k {
			case TokenFieldPolicies:
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, configPath, tAttrs...)
	}
}

func testLDAPAuthBackendConfig_basic(path, use_token_groups, local, extraConfig string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path                   = "%s"
    local                  = %s
    url                    = "ldaps://example.org"
    starttls               = true
    case_sensitive_names   = false
    tls_min_version        = "tls11"
    tls_max_version        = "tls12"
    insecure_tls           = false
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    discoverdn             = false
    deny_null_bind         = true
    description            = "example"
    userfilter             = "({{.UserAttr}}={{.Username}})"
    username_as_alias      = true
    use_token_groups       = %s
    connection_timeout     = 30
	%s
}
`, path, local, use_token_groups, extraConfig)
}

func testLDAPAuthBackendConfig_params(path string, request_timeout int, dereference_aliases string, enable_samaccountname_login bool, anonymous_group_search bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
	path                 = "%s"
   	url                  = "ldaps://ldap.example.com"
   	userdn               = "ou=Users,dc=example,dc=com"
   	groupdn              = "ou=Groups,dc=example,dc=com"
   	binddn               = "cn=admin,dc=example,dc=com"
	bindpass             = "your-ldap-password"
  	userattr             = "uid"
	groupattr            = "cn"
	insecure_tls          = false
	starttls              = false
	discoverdn            = true
	case_sensitive_names  = false
	request_timeout               = %d
	dereference_aliases           = "%s"
	enable_samaccountname_login   = %t
	anonymous_group_search        = %t
}
`, path, request_timeout, dereference_aliases, enable_samaccountname_login, anonymous_group_search)
}

func testLDAPAuthBackendConfig_defaults(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
	path                 = "%s"
   	url                  = "ldaps://ldap.example.com"
   	userdn               = "ou=Users,dc=example,dc=com"
   	groupdn              = "ou=Groups,dc=example,dc=com"
   	binddn               = "cn=admin,dc=example,dc=com"
	bindpass             = "your-ldap-password"
  	userattr             = "uid"
	groupattr            = "cn"
	insecure_tls         = false
	starttls             = false
	discoverdn           = true
	case_sensitive_names = false
	# request_timeout, dereference_aliases, enable_samaccountname_login, and anonymous_group_search
	# are intentionally omitted to test that Vault returns default/computed values
}
`, path)
}

func testLDAPAuthBackendConfig_tls(path, use_token_groups string, local string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path                   = "%s"
    local                  = %s
    url                    = "ldaps://example.org"
    starttls               = true
    tls_min_version        = "tls11"
    tls_max_version        = "tls12"
    insecure_tls           = false
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    discoverdn             = false
    deny_null_bind         = true
    description            = "example"
    certificate            = <<EOT
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUahce2sCO7Bom/Rznd5HsNAlr1NgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODEyMDIwMTAxNDRaFw00NjEy
MTUwMTAxNDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDC8Qd4kJecWCLzysTV1NfoUd0E8rTBKN52HTLBWcJn
EtZsG//k/K2NNwI92t9buDax9s/A6B79YXdfYp5hI/xLFkDRzObPpAOyl4b3bUmR
la3Knmj743SV4tMhQCGrff2nc7WicA5Q7WTiwd+YLB+sOlOfaFzHhRFrk/PNvV8e
KC6yMgfWZwZ2dxoDpnYLM7XDgTyQ85S6QgOtxlPh9o5mtZQhBkpDDYnNPIon5kwM
JmrZMXNbCkvd4bjzAHsnuaJsVD/2cW/Gkh+UGMMBnxCKqTBivk3QM2xPFx9MJJ65
t8kMJR8hbAVmEuK3PA7FrNrNRApdf9I8xDWX8v2jeecfAgMBAAGjUzBRMB0GA1Ud
DgQWBBQXGfrns8OqxTGKsXG5pDZS/WyyYDAfBgNVHSMEGDAWgBQXGfrns8OqxTGK
sXG5pDZS/WyyYDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCt
8aUX26cl2PgdIEByZSHAX5G+2b0IEtTclPkl4uDyyKRY4dVq6gK3ueVSU5eUmBip
JbV5aRetovGOcV//8vbxkZm/ntQ8Oo+2sfGR5lIzd0UdlOr5pkD6g3bFy/zJ+4DR
DAe8fklUacfz6CFmD+H8GyHm+fKmF+mjr4oOGQW6OegRDJHuiipUk2lJyuXdlPSa
FpNRO2sGbjn000ANinFgnFiVzGDnx0/G1Kii/6GWrI6rrdVmXioQzF+8AloWckeB
+hbmbwkwQa/JrLb5SWcBDOXSgtn1Li3XF5AQQBBjA3pOlyBXqnI94Irw89Lv9uPT
MUR4qFxeUOW/GJGccMUd
-----END CERTIFICATE-----
EOT
    client_tls_cert        = <<EOT
-----BEGIN CERTIFICATE-----
MIID3jCCAsagAwIBAgIUFQKX5kCu6lBK60jF6HYPZH0v9oIwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTA2MDkwOTAzMDdaFw0zMTA2
MDcwOTAzMDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDRCYt5o89zZnQY65bC2sohOgEJa7CrLyPo4/2B/elC
UN7lGSH3NA/kAGIR6ZHl7pOTiXFfvTjkLdpp7IXw2YI/D/tfyYFp5OeO6GxQdrpp
0ctNia9mektigzNkiTXcWi0f3ye9TfKYP2ThJfHjua/2kYsVKtgCGZjou+qShKhm
KFNjIUMXf+1tyQmVu26pVc5OjnBETVyrJqZSbPSEoI0sDb231rsQN/NV5/tbtxDC
4ywm60bpgaqpIrhip1swp3XYn3CSfjGtzJuv9xMTJQ+bbS6A5Sncy+I69qlxbgwr
P7ny60xp2quT18qHQwH93fKbBypO4QfFlULogWkYw1nNAgMBAAGjgcUwgcIwCQYD
VR0TBAIwADARBglghkgBhvhCAQEEBAMCBaAwMwYJYIZIAYb4QgENBCYWJE9wZW5T
U0wgR2VuZXJhdGVkIENsaWVudCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU84RskljZ
wD5J+rinRsA4eykTS+owHwYDVR0jBBgwFoAUFxn657PDqsUxirFxuaQ2Uv1ssmAw
DgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAN
BgkqhkiG9w0BAQsFAAOCAQEANPokK0qpj1/b0hSrjImz1XD1N4QTKn47hV6hBhgr
6MYKwBRVj8e0Ly/qgmipprP8hQsBtZPaUh98ZXu9dI5br7jPD/NKv9EpFVHAHWxP
a4xuw2ibp4MdDSSsLxwV91KE/unoka1RjFZO6aLT+yS9Fkzyov5mWHh56nYdnpnv
ATFy+UpXn9+16ddPBGALGlOmDaEHWImMEc2dIN6/GvtOpmUD/cr7fbsIN8leRgzZ
suX9kmcMCISHk6aa5gWcRIBWPwxANNHUDL/+A6KAo36zM/dx8vln9XhftSEnxSFw
6Z5nUoT9l/5TSGwK/AIkS4ApBDOytf/YiAq01QR9ENRGRQ==
-----END CERTIFICATE-----
EOT
    client_tls_key         = <<EOT
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0QmLeaPPc2Z0GOuWwtrKIToBCWuwqy8j6OP9gf3pQlDe5Rkh
9zQP5ABiEemR5e6Tk4lxX7045C3aaeyF8NmCPw/7X8mBaeTnjuhsUHa6adHLTYmv
ZnpLYoMzZIk13FotH98nvU3ymD9k4SXx47mv9pGLFSrYAhmY6LvqkoSoZihTYyFD
F3/tbckJlbtuqVXOTo5wRE1cqyamUmz0hKCNLA29t9a7EDfzVef7W7cQwuMsJutG
6YGqqSK4YqdbMKd12J9wkn4xrcybr/cTEyUPm20ugOUp3MviOvapcW4MKz+58utM
adqrk9fKh0MB/d3ymwcqTuEHxZVC6IFpGMNZzQIDAQABAoIBAQCdi1UMM1KZheEA
Gya/6sembSH06K35BolI7/PTMfvIWEz1W5DGz/0d+M/w8hlcsweUjWTeJC2pg4l2
haWZFUVdo/zvf15C4htHEJL5vdHXCR/xa1C/qnIAaCOmpObsESarO7OmsAWjizvL
mJ6K5BrjeWPaazTruEEPPvmWvdZxTpx/vmnwnB8fhHdtMbkSCAqCyc/fUqJgAGLU
1QXFeTcasW39jtAdutJq98UR2yOYiknU7xwDUAALwcVM14p4GmsBUM8Sf5JbYK2c
EoBJk/aDJiK+fLgRinH76FNpTknvdH3hGfwotXwanSBKj3DzAQwY3JWXC5kIFdcL
HjhtiOjhAoGBAOfetKHANyFgWwiVdRLmUA42K1r/1yvrisKycxJl4HeYI27VsQNI
ffOLMkxLj8ahuXlzlceXUDvf78gkwydk8UGCvpFt1+da79rKfCGVogeNUmaExKke
+uFEoOrjWqaxtE/gRYmZlES9dhSnGQZH+r/V5HhxHrQI0MgAAITFMstZAoGBAObK
jLl6ShwYG9A97howUxJRaGmyTk3iMMzu1cKoP4OGCFrsYnaiG/dK/b85stz/55ks
aZjUR3anpUyedIo1DiB/Iqq0ues2UIo+adUno9Fyf+aI8x+gs4fsdbn8TXBMTPgC
XQxm+wsC2EKIB6IlttZRTdhvLOHiw5/PkoApnheVAoGBANwtRikydSdkcA0+nuVL
fkmAdrr6pkA2cpVfDpYx12y5MyxUDrqnY7KYQzLfra9Yct85OslEjhPNGcxb3FTU
LaOfm4ZNX+95EroX/LeHd0zkjZJ8EKLnoCO5H3TsX3Ba3nXa6S04gOqlXjNOWRz1
zM3NNh6IjDc5B8hi+BsbhphBAoGAfXgOi2N1WNKuhEa25FvzPZkuZ4/9TBA1MaSC
Z8IqTWmXrz6lxRMamxWU39oRaF5jXX2spt55P4OitQXMG7r+RCJ6CU4ZaUts+8s0
pCJZyCs0Z3N6oW4vTCz8T7FftDZ2/bnjNjPiNTlFst3bMIbKYLdw18KRJviuG3qw
jaaSgQUCgYEAhPaS+90L+Y01mDPH+adkhCYy4hoZlF2cOf0DJFzQ2CdNkoK1Cv9V
pIth9roSSN2mcYxH5P7uVIFm7jJ3tI4ExQdtJkPed/GK1DC7l2VGOi+TtCdm004r
MvQzNd87hRypUZ9Hyx2C9RljNDHHjgwYwWv9JOT0xEOS4ZAaPfvTf20=
-----END RSA PRIVATE KEY-----
EOT
    use_token_groups = %s
	request_timeout        = 60
    dereference_aliases    = "always"
    enable_samaccountname_login = true
    anonymous_group_search = false
}
`, path, local, use_token_groups)
}

func testLDAPAuthBackendConfig_automatedRotation(path string, useTokenGroups, local bool, schedule string, window, period int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path                   = "%s"
    local                  = %t
    url                    = "ldaps://example.org"
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    use_token_groups = %t
	 rotation_schedule = "%s"
    rotation_window   = "%d"
    rotation_period   = "%d"
    disable_automated_rotation = %t
}
`, path, local, useTokenGroups, schedule, window, period, disable)
}

func testLDAPAuthBackend_tune_partial(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
	path = "%s"
	url = "ldaps://example.org"
	binddn = "cn=example.com"
	bindpass = "supersecurepassword"
	tune {
		audit_non_hmac_request_keys = ["key1"]
		audit_non_hmac_response_keys = ["key3"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, path)
}

func testLDAPAuthBackend_tune_full(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
	path = "%s"
	url = "ldaps://example.org"
	binddn = "cn=example.com"
	bindpass = "supersecurepassword"
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
`, path)
}

func testLDAPAuthBackendConfig_denyNullBindNotSet(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path        = "%s"
    url         = "ldaps://example.org"
    binddn      = "cn=example.com"
    bindpass    = "supersecurepassword"
    description = "Test LDAP auth backend for deny_null_bind behavior"
    # deny_null_bind is intentionally not set to test default behavior
}
`, path)
}

func testLDAPAuthBackendConfig_denyNullBindExplicitFalse(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path            = "%s"
    url             = "ldaps://example.org"
    binddn          = "cn=example.com"
    bindpass        = "supersecurepassword"
    description     = "Test LDAP auth backend for deny_null_bind behavior"
    deny_null_bind  = false
}
`, path)
}

func testLDAPAuthBackendConfig_bindpassWO(path, bindpass string, version int) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path               = "%s"
    url                = "ldaps://example.org"
    binddn             = "cn=example.com"
    bindpass_wo        = "%s"
    bindpass_wo_version = %d
    description        = "Test LDAP auth backend with write-only bindpass"
}
`, path, bindpass, version)
}

func testLDAPAuthBackendConfig_bindpassConflict(path string) string {
	return fmt.Sprintf(`
resource "vault_ldap_auth_backend" "test" {
    path               = "%s"
    url                = "ldaps://example.org"
    binddn             = "cn=example.com"
    bindpass           = "supersecurepassword"
    bindpass_wo        = "anothersecurepassword"
    bindpass_wo_version = 1
    description        = "Test LDAP auth backend with conflicting bindpass"
}
`, path)
}
