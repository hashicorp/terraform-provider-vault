// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccJWTAuthBackend(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("jwt")
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".jwt"

	getSteps := func(path, ns string) []resource.TestStep {
		var commonChecks []resource.TestCheckFunc
		if ns != "" {
			commonChecks = append(commonChecks,
				resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
			)
		}

		steps := []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig(path, ns, false),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "description", "JWT backend"),
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "path", path),
						resource.TestCheckResourceAttrSet(resourceName, "accessor"),
						resource.TestCheckResourceAttr(resourceName, "bound_issuer", ""),
						resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
						resource.TestCheckResourceAttr(resourceName, "local", "false"),
					)...,
				),
			},
			{
				Config: testAccJWTAuthBackendConfig(path, ns, true),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "description", "JWT backend"),
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "path", path),
						resource.TestCheckResourceAttrSet(resourceName, "accessor"),
						resource.TestCheckResourceAttr(resourceName, "bound_issuer", ""),
						resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
						resource.TestCheckResourceAttr(resourceName, "local", "true"),
					)...,
				),
			},
			{
				Config: testAccJWTAuthBackendConfigFullOIDC(path, "https://myco.auth0.com/", "api://default", "\"RS512\"", ns),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "bound_issuer", "api://default"),
						resource.TestCheckResourceAttr(resourceName, "jwt_supported_algs.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
					)...,
				),
			},
			{
				Config: testAccJWTAuthBackendConfigFullOIDC(path, "https://myco.auth0.com/", "api://default", "\"RS256\",\"RS512\"", ns),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "bound_issuer", "api://default"),
						resource.TestCheckResourceAttr(resourceName, "jwt_supported_algs.#", "2"),
						resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
					)...,
				),
			},
		}

		return steps
	}

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestAccPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("jwt")
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestEntPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ns),
		})
	},
	)
}

func TestAccJWTAuthBackendProviderConfig(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("oidc")
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".oidc"
	getSteps := func(path, ns string) []resource.TestStep {
		var commonChecks []resource.TestCheckFunc
		if ns != "" {
			commonChecks = append(commonChecks,
				resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
			)
		}
		steps := []resource.TestStep{
			{
				Config: testAccJWTAuthBackendProviderConfig(path, ns),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "type", "oidc"),
						resource.TestCheckResourceAttr(resourceName, "provider_config.provider", "azure"),
						resource.TestCheckResourceAttr(resourceName, "provider_config.groups_recurse_max_depth", "1"),
					)...,
				),
			},
		}

		return steps
	}

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestAccPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("jwt")
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestEntPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ns),
		})
	},
	)
}

func TestAccJWTAuthBackend_OIDC(t *testing.T) {
	t.Parallel()
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".oidc"
	getSteps := func(path, ns string) []resource.TestStep {
		var commonChecks []resource.TestCheckFunc
		if ns != "" {
			commonChecks = append(commonChecks,
				resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
			)
		}
		steps := []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfigOIDC(path, ns),
				Check: resource.ComposeTestCheckFunc(
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
						resource.TestCheckResourceAttr(resourceName, "bound_issuer", "api://default"),
						resource.TestCheckResourceAttr(resourceName, "oidc_client_id", "client"),
						resource.TestCheckResourceAttr(resourceName, "oidc_client_secret", "secret"),
						resource.TestCheckResourceAttr(resourceName, "oidc_response_mode", "query"),
						resource.TestCheckResourceAttr(resourceName, "oidc_response_types.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "oidc_response_types.0", "code"),
						resource.TestCheckResourceAttr(resourceName, "type", "oidc"),
						resource.TestCheckResourceAttr(resourceName, "default_role", "api"),
					)...,
				),
			},
		}

		return steps
	}

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		path := acctest.RandomWithPrefix("oidc")
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestAccPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("oidc")
		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testutil.TestEntPreCheck(t) },
			ProviderFactories: providerFactories,
			CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:             getSteps(path, ns),
		})
	},
	)
}

func TestAccJWTAuthBackend_invalid(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("jwt")
	invalidPath := path + consts.PathDelim
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:  testAccJWTAuthBackendConfig(invalidPath, "", false),
				Destroy: false,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "%s" for "path" contains leading/trailing "%s"`,
						invalidPath, consts.PathDelim)),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "jwt" {
				  description = "JWT backend"
				  oidc_discovery_url = "%s"
				  jwt_validation_pubkeys = [%s]
				  bound_issuer = "%s"
				  jwt_supported_algs = [%s]
				  path = "%s"
				}`, "https://myco.auth0.com/", "\"key\"", "api://default", "", path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
		},
	})
}

func TestJWTAuthBackend_remount(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-jwt")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-jwt-updated")

	resourceName := "vault_jwt_auth_backend.jwt"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig(path, "", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "JWT backend"),
					resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttrSet(resourceName, "accessor"),
					resource.TestCheckResourceAttr(resourceName, "bound_issuer", ""),
					resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testAccJWTAuthBackendConfig(updatedPath, "", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "JWT backend"),
					resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttrSet(resourceName, "accessor"),
					resource.TestCheckResourceAttr(resourceName, "bound_issuer", ""),
					resource.TestCheckResourceAttr(resourceName, "type", "jwt"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "disable_remount"),
		},
	})
}

func testAccJWTAuthBackendConfig(path, ns string, local bool) string {
	c := fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description        = "JWT backend"
  oidc_discovery_url = "https://myco.auth0.com/"
  path               = "%s"
  local              = %t
`, path, local)

	var fragments []string
	if ns != "" {
		fragments = []string{
			fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns),
		}
		c += `
  namespace = vault_namespace.test.path
`
	}

	config := strings.Join(append(fragments, c, "}"), "\n")
	return config
}

func testAccJWTAuthBackendConfigFullOIDC(path string, oidcDiscoveryUrl string, boundIssuer string, supportedAlgs string, ns string) string {
	config := fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description        = "JWT backend"
  oidc_discovery_url = "%s"
  bound_issuer       = "%s"
  jwt_supported_algs = [%s]
  path               = "%s"
`, oidcDiscoveryUrl, boundIssuer, supportedAlgs, path)

	var fragments []string
	if ns != "" {
		fragments = []string{
			fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns),
		}
		config += `
  namespace = vault_namespace.test.path
`
	}

	return strings.Join(append(fragments, config, "}"), "\n")
}

func testAccJWTAuthBackendConfigOIDC(path string, ns string) string {
	config := fmt.Sprintf(`
resource "vault_jwt_auth_backend" "oidc" {
  description         = "OIDC backend"
  oidc_discovery_url  = "https://myco.auth0.com/"
  oidc_client_id      = "client"
  oidc_client_secret  = "secret"
  bound_issuer        = "api://default"
  path                = "%s"
  type                = "oidc"
  default_role        = "api"
  oidc_response_mode  = "query"
  oidc_response_types = ["code"]
`, path)

	var fragments []string
	if ns != "" {
		fragments = []string{
			fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns),
		}
		config += `
  namespace = vault_namespace.test.path
`
	}

	return strings.Join(append(fragments, config, "}"), "\n")
}

func testAccJWTAuthBackendProviderConfig(path string, ns string) string {
	config := fmt.Sprintf(`
resource "vault_jwt_auth_backend" "oidc" {
  description        = "OIDC backend"
  oidc_discovery_url = "https://myco.auth0.com/"
  path               = "%s"
  type               = "oidc"
  provider_config = {
    provider                 = "azure"
    groups_recurse_max_depth = "1"
  }
`, path)

	var fragments []string
	if ns != "" {
		fragments = []string{
			fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns),
		}
		config += `
  namespace = vault_namespace.test.path
`
	}

	return strings.Join(append(fragments, config, "}"), "\n")
}

func TestAccJWTAuthBackend_missingMandatory(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("jwt")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
						path = "%s"
						oidc_discovery_url = ""
					}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwks_url = ""
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwt_validation_pubkeys = []
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`
				resource "vault_identity_oidc_key" "key" {
					name = "com"
				}

				resource "vault_jwt_auth_backend" "unknown" {
					path = "%s"
					// force value to be unknown until apply phase
					oidc_discovery_url = "https://myco.auth0.${vault_identity_oidc_key.key.id}/"
				}`, path),
			},
		},
	})
}

func TestAccJWTAuthBackendProviderConfigConversionBool(t *testing.T) {
	t.Parallel()
	type test struct {
		name  string
		value string
		err   bool
		want  interface{}
	}

	tests := []test{
		{name: "fetch_groups", value: "true", err: false, want: true},
		{name: "fetch_groups", value: "TRUE", err: false, want: true},
		{name: "fetch_groups", value: "false", err: false, want: false},
		{name: "fetch_groups", value: "FALSE", err: false, want: false},
		{name: "fetch_groups", value: "foo", err: true, want: ""},

		{name: "fetch_user_info", value: "true", err: false, want: true},
		{name: "fetch_user_info", value: "TRUE", err: false, want: true},
		{name: "fetch_user_info", value: "false", err: false, want: false},
		{name: "fetch_user_info", value: "FALSE", err: false, want: false},
		{name: "fetch_user_info", value: "foo", err: true, want: ""},
	}

	for _, tc := range tests {
		config := map[string]interface{}{
			tc.name: tc.value,
		}
		actual, err := convertProviderConfigValues(config)
		if tc.err && err == nil {
			t.Fatalf("expected error, got none for key: %s, value: %s", tc.name, tc.value)
		} else if !tc.err && err != nil {
			t.Fatalf("expected no error, got one: %s", err)
		} else if !tc.err {
			if actual[tc.name] != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, actual[tc.name])
			}
		}
	}
}

func TestAccJWTAuthBackendProviderConfigConversionInt(t *testing.T) {
	t.Parallel()
	type test struct {
		name  string
		value string
		err   bool
		want  interface{}
	}

	tests := []test{
		{name: "groups_recurse_max_depth", value: "1", err: false, want: int64(1)},
		{name: "groups_recurse_max_depth", value: "0", err: false, want: int64(0)},
		{name: "groups_recurse_max_depth", value: "-1", err: false, want: int64(-1)},
		{name: "groups_recurse_max_depth", value: "foo", err: true, want: int64(0)},
	}

	for _, tc := range tests {
		config := map[string]interface{}{
			tc.name: tc.value,
		}
		actual, err := convertProviderConfigValues(config)
		if tc.err && err == nil {
			t.Fatalf("exepcted error, got none for key: %s, value: %s", tc.name, tc.value)
		} else if !tc.err && err != nil {
			t.Fatalf("expected no error, got one: %s", err)
		} else if !tc.err {
			if actual[tc.name] != tc.want {
				t.Fatalf("exepcted %s, got %s", tc.want, actual[tc.name])
			}
		}
	}
}

// Testing bad values here for various parameters. This test leaks backends that don't get
// cleaned up because a race condition exists that make it hard to get the error
// before Terraform destroys the resource. Since we are creating both a Vault mount
// and configuring it in a single resource, the mount creation succeeds but the config fails.
// There seems to be a race condition if you destroy the resource, so auth backends never
// get deleted because only the config failed.
// Leaving this test here for now until we can update to newer versions of SDK, which might
// have resolved this race condition.
func TestAccJWTAuthBackendProviderConfig_negative(t *testing.T) {
	t.Skip(true)
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "oidc" {
					description = "OIDC Backend"
					oidc_discovery_url = "https://myco.auth0.com/"
					path = "%s"
					type = "oidc"
					provider_config = {
						provider = "azure"
						fetch_groups = "foo"
					}
				  }`, acctest.RandomWithPrefix("oidc")),
				Destroy:     false,
				ExpectError: regexp.MustCompile("could not convert fetch_groups to bool: strconv.ParseBool: parsing \"foo\": invalid syntax"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "oidc" {
					description = "OIDC Backend"
					oidc_discovery_url = "https://myco.auth0.com/"
					path = "%s"
					type = "oidc"
					provider_config = {
						provider = "azure"
						fetch_user_info = "foo"
					}
				  }`, acctest.RandomWithPrefix("oidc")),
				Destroy:     false,
				ExpectError: regexp.MustCompile("could not convert fetch_user_info to bool: strconv.ParseBool: parsing \"foo\": invalid syntax"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "oidc" {
					description = "OIDC Backend"
					oidc_discovery_url = "https://myco.auth0.com/"
					path = "%s"
					type = "oidc"
					provider_config = {
						provider = "azure"
						groups_recurse_max_depth = "foo"
					}
				  }`, acctest.RandomWithPrefix("oidc")),
				Destroy:     false,
				ExpectError: regexp.MustCompile("could not convert groups_recurse_max_depth to int: strconv.ParseInt: parsing \"foo\": invalid syntax"),
			},
		},
	})
}
