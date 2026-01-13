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
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
						resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
						resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
						// ensure the global default effect from Vault tune API is ignored,
						// these fields should stay empty
						resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", ""),
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
						resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
						resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
						// ensure the global default effect from Vault tune API is ignored,
						// these fields should stay empty
						resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", ""),
						resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", ""),
					)...,
				),
			},
		}

		return steps
	}

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("jwt")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ns),
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
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("jwt")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ns),
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
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ""),
		})
	},
	)

	t.Run("ns", func(t *testing.T) {
		t.Parallel()
		ns := acctest.RandomWithPrefix("ns")
		path := acctest.RandomWithPrefix("oidc")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
			Steps:                    getSteps(path, ns),
		})
	},
	)
}

func TestAccJWTAuthBackend_invalid(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("jwt")
	invalidPath := path + consts.PathDelim
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "jwt" {
				  description = "JWT backend"
				  jwks_url = "%s"
				  bound_issuer = "%s"
				  path = "%s"
				  jwks_pairs = %s
				}`, "https://www.foobar.com/certs", "api://default", path,
					`[
					  	{
							jwks_url = "https://www.foobar.com/certs" 
							jwks_ca_pem = "cert"
					  	}
					]`,
				),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "jwt" {
				  description = "JWT backend"
				  jwks_ca_pem = "%s"
				  bound_issuer = "%s"
				  path = "%s"
				  jwks_pairs = %s
				}`, "cert", "api://default", path,
					`[
					  	{
							jwks_url = "https://www.foobar.com/certs" 
							jwks_ca_pem = "cert"
					  	}
					]`,
				),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
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
  tune {
	passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
  }
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
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
						path = "%s"
						oidc_discovery_url = ""
					}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwks_url = ""
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwt_validation_pubkeys = []
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwks_pairs= []
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided"),
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
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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

// TestAccJWTAuthBackendJWKSPairs_expectedError tests that the bad jwks_pairs argument
// fails with expected errors
// We are not testing the Vault API here, just that the provider delivers the config to Vault
// and that Vault returns the expected error.
func TestAccJWTAuthBackendJWKSPairs_expectedError(t *testing.T) {
	const caPEM = `<<EOT
-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIQEP/md970HysdBTpuzDOf0DANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAxcl69ROJdxjN+MJZnbFrYxyQooADCsJ6VDkuMyNQIix/Hk15Nk/u
FyBX1Me++aEpGmY3RIY4fUvELqT/srvAHsTXwVVSttMcY8pcAFmXSqo3x4MuUTG/
jCX3Vftj0r3EM5M8ImY1rzA/jqTTLJg00rD+DmuDABcqQvoXw/RV8w1yTRi5BPoH
DFD/AWTt/YgMvk1l2Yq/xI8VbMUIpjBoGXxWsSevQ5i2s1mk9/yZzu0Ysp1tTlzD
qOPa4ysFjBitdXiwfxjxtv5nXqOCP5rheKO0sWLk0fetMp1OV5JSJMAJw6c2ZMkl
U2WMqAEpRjdE/vHfIuNg+yGaRRqI07NZRQIDAQABo4GXMIGUMA4GA1UdDwEB/wQE
AwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBQR5QIzmacmw78ZI1C4MXw7Q0wJ1jA9BgNVHREENjA0ggtleGFtcGxlLmNv
bYINKi5leGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG
9w0BAQsFAAOCAQEACrRNgiioUDzxQftd0fwOa6iRRcPampZRDtuaF68yNHoNWbOu
LUwc05eOWxRq3iABGSk2xg+FXM3DDeW4HhAhCFptq7jbVZ+4Jj6HeJG9mYRatAxR
Y/dEpa0D0EHhDxxVg6UzKOXB355n0IetGE/aWvyTV9SiDs6QsaC57Q9qq1/mitx5
2GFBoapol9L5FxCc77bztzK8CpLujkBi25Vk6GAFbl27opLfpyxkM+rX/T6MXCPO
6/YBacNZ7ff1/57Etg4i5mNA6ubCpuc4Gi9oYqCNNohftr2lkJr7REdDR6OW0lsL
rF7r4gUnKeC7mYIH1zypY7laskopiLFAfe96Kg==
-----END CERTIFICATE-----
EOT`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "foo" {
					type = "jwt"
					path = "%s"
					jwks_pairs = [
						{
							jwks_url = "https://www.foobar.com/certs"
							jwks_ca_pem = %s
						}
					]
				  }`, acctest.RandomWithPrefix("jwt"), caPEM),
				Destroy:     false,
				ExpectError: regexp.MustCompile("error checking jwks URL"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "foo" {
					type = "jwt"
					path = "%s"
					jwks_pairs = [
						{
							jwks_url = "https://www.foobar.com/certs"
							jwks_ca_pem = "invalid CA PEM"
						}
					]
				  }`, acctest.RandomWithPrefix("jwt")),
				Destroy:     false,
				ExpectError: regexp.MustCompile("error checking jwks_ca_pem"),
			},
		},
	})
}

func TestAccJWTAuthBackend_importTune(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("jwt")
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig_tuning(path),
				Check: testutil.TestAccCheckAuthMountExists(resourceName,
					&resAuth,
					testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "disable_remount"),
		},
	})
}

func testAccJWTAuthBackendConfig_tuning(path string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  description        = "JWT backend"
  oidc_discovery_url = "https://myco.auth0.com/"
  path			     = "%s"
  tune {
    default_lease_ttl = "10m"
    max_lease_ttl = "20m"
    listing_visibility = "hidden"
    audit_non_hmac_request_keys = ["key1", "key2"]
    audit_non_hmac_response_keys = ["key3", "key4"]
    passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
    allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
    token_type = "batch"
  }
}
`, path)
}

func TestAccJWTAuthBackend_OIDCClientSecretWriteOnly(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("oidc-wo")
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig_OIDCClientSecretWriteOnly(path, "secret-v1", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "type", "oidc"),
					resource.TestCheckResourceAttr(resourceName, "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr(resourceName, "oidc_client_id", "test-client-id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOIDCClientSecretWOVersion, "1"),
					// Verify that legacy oidc_client_secret is not set
					resource.TestCheckNoResourceAttr(resourceName, "oidc_client_secret"),
					// Note: oidc_client_secret_wo is write-only and won't be in state
				),
			},
			{
				// Update the secret by incrementing version
				Config: testAccJWTAuthBackendConfig_OIDCClientSecretWriteOnly(path, "secret-v2", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOIDCClientSecretWOVersion, "2"),
				),
			},
			{
				// Change other fields without changing secret (same version)
				Config: testAccJWTAuthBackendConfig_OIDCClientSecretWriteOnlyUpdated(path, "secret-v2", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "oidc_client_id", "updated-client-id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOIDCClientSecretWOVersion, "2"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackend_OIDCClientSecretLegacy(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("oidc-legacy")
	resourceType := "vault_jwt_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeJWT, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig_OIDCClientSecretLegacy(path, "legacy-secret-v1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "type", "oidc"),
					resource.TestCheckResourceAttr(resourceName, "oidc_client_secret", "legacy-secret-v1"),
					// Verify write-only fields are not set
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldOIDCClientSecretWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldOIDCClientSecretWOVersion),
				),
			},
			{
				Config: testAccJWTAuthBackendConfig_OIDCClientSecretLegacy(path, "legacy-secret-v2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "oidc_client_secret", "legacy-secret-v2"),
				),
			},
		},
	})
}

func testAccJWTAuthBackendConfig_OIDCClientSecretWriteOnly(path, secret string, version int) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  path                        = "%s"
  type                        = "oidc"
  description                 = "OIDC backend with write-only secret"
  oidc_discovery_url          = "https://myco.auth0.com/"
  oidc_client_id              = "test-client-id"
  oidc_client_secret_wo       = "%s"
  oidc_client_secret_wo_version = %d
  default_role                = "test-role"
}
`, path, secret, version)
}

func testAccJWTAuthBackendConfig_OIDCClientSecretWriteOnlyUpdated(path, secret string, version int) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  path                        = "%s"
  type                        = "oidc"
  description                 = "OIDC backend with write-only secret - updated"
  oidc_discovery_url          = "https://myco.auth0.com/"
  oidc_client_id              = "updated-client-id"
  oidc_client_secret_wo       = "%s"
  oidc_client_secret_wo_version = %d
  default_role                = "test-role"
}
`, path, secret, version)
}

func testAccJWTAuthBackendConfig_OIDCClientSecretLegacy(path, secret string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  path                = "%s"
  type                = "oidc"
  description         = "OIDC backend with legacy secret"
  oidc_discovery_url  = "https://myco.auth0.com/"
  oidc_client_id      = "test-client-id"
  oidc_client_secret  = "%s"
  default_role        = "test-role"
}
`, path, secret)
}

func TestAccJWTAuthBackend_OIDCClientSecretWriteOnlyConflicts(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("oidc-conflicts")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			// Negative Test 1: oidc_client_secret and oidc_client_secret_wo cannot be used together
			{
				Config:      testAccJWTAuthBackendConfig_OIDCClientSecretConflict(path, "secret", 1),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			// Negative Test 2: oidc_client_secret_wo_version requires oidc_client_secret_wo
			{
				Config:      testAccJWTAuthBackendConfig_OIDCClientSecretVersionWithoutSecret(path),
				ExpectError: regexp.MustCompile(`all of\s+.+oidc_client_secret_wo.+oidc_client_secret_wo_version.+ must be specified`),
			},
		},
	})
}

// Negative test configs
func testAccJWTAuthBackendConfig_OIDCClientSecretConflict(path, secret string, version int) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  path                          = "%s"
  type                          = "oidc"
  description                   = "OIDC backend with conflicting secrets"
  oidc_discovery_url            = "https://myco.auth0.com/"
  oidc_client_id                = "test-client-id"
  oidc_client_secret            = "%s"
  oidc_client_secret_wo         = "%s"
  oidc_client_secret_wo_version = %d
  default_role                  = "test-role"
}
`, path, secret, secret, version)
}

func testAccJWTAuthBackendConfig_OIDCClientSecretVersionWithoutSecret(path string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "test" {
  path                          = "%s"
  type                          = "oidc"
  description                   = "OIDC backend with version but no secret_wo"
  oidc_discovery_url            = "https://myco.auth0.com/"
  oidc_client_id                = "test-client-id"
  oidc_client_secret            = "legacy-secret"
  oidc_client_secret_wo_version = 1
  default_role                  = "test-role"
}
`, path)
}
