// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccJWTAuthBackendRole_import(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_full(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.2", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "12"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.0", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/groups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"clock_skew_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"expiration_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"not_before_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"verbose_oidc_logging", "true"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim_json_pointer", "true"),
				),
			},
			{
				ResourceName:            "vault_jwt_auth_backend_role.role",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"disable_bound_claims_parsing"},
			},
		},
	})
}

func TestAccJWTAuthBackendRole_basic(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_basic(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim_json_pointer", "false"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_basic(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
				),
			},
			{
				Config: testAccJWTAuthBackendRoleConfig_update(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_full(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_full(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.2", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "12"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.0", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/groups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"clock_skew_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"expiration_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"not_before_leeway", "120"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"verbose_oidc_logging", "true"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRoleOIDC_full(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	backend := acctest.RandomWithPrefix("oidc")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfigOIDC_full(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.2", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "12"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.0", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/groups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"allowed_redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"allowed_redirect_uris.0", "http://localhost:8080"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.%", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.department", "engineering,admin"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.sector", "7g"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"claim_mappings.%", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"claim_mappings.group", "group"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"claim_mappings.preferred_language", "language"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"verbose_oidc_logging", "true"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim_json_pointer", "true"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_age", "120"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRoleOIDC_disableParsing(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfigOIDC_disableParsing(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "string"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.%", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.department", "engineering,admin"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.sector", "7g"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"disable_bound_claims_parsing", "true"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_fullUpdate(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	initialChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"backend", backend),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"role_name", role),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_policies.#", "3"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_policies.0", "default"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_policies.2", "prod"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_policies.1", "dev"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_ttl", "3600"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_max_ttl", "7200"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_num_uses", "12"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_period", "0"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_bound_cidrs.#", "2"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_bound_cidrs.0", "10.148.0.0/20"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"token_bound_cidrs.1", "10.150.0.0/20"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"bound_audiences.#", "1"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"bound_audiences.0", "https://myco.test"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"user_claim", "https://vault/user"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"groups_claim", "https://vault/groups"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"clock_skew_leeway", "120"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"expiration_leeway", "120"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"not_before_leeway", "120"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"verbose_oidc_logging", "true"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"bound_claims.%", "0"),
		resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
			"user_claim_json_pointer", "true"),
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_full(backend, role),
				Check:  resource.ComposeAggregateTestCheckFunc(initialChecks...),
			},
			{
				Config: testAccJWTAuthBackendRoleConfig_fullUpdate(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_max_ttl", "10800"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_num_uses", "24"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.0", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.1", "10.152.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.0", "https://myco.update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/updateuser"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/updategroups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims_type", "glob"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.%", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.department", "engineering-*-admin"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_claims.sector", "7g"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"clock_skew_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"expiration_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"not_before_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"verbose_oidc_logging", "false"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim_json_pointer", "false"),
				),
			},
			// Repeat test case again to remove attributes like `bound_claims`
			{
				Config: testAccJWTAuthBackendRoleConfig_full(backend, role),
				Check:  resource.ComposeAggregateTestCheckFunc(initialChecks...),
			},
		},
	})
}

func testAccCheckJWTAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_jwt_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for JWT auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("JWT auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccJWTAuthBackendRoleConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_auth_backend.jwt.path
  role_name = "%s"
  role_type = "jwt"

  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_update(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_auth_backend.jwt.path
  role_name = "%s"
  role_type = "jwt"

  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  token_policies = ["default", "dev"]
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_full(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_auth_backend.jwt.path
  role_name = "%s"
  role_type = "jwt"

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"
  token_bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  groups_claim = "https://vault/groups"
  token_policies = ["default", "dev", "prod"]
  token_ttl = 3600
  token_num_uses = 12
  token_max_ttl = 7200

  clock_skew_leeway = 120
  expiration_leeway = 120
  not_before_leeway = 120

  verbose_oidc_logging = true
  user_claim_json_pointer = true
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfigOIDC_full(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  type = "oidc"
  path = "%s"
  oidc_discovery_url = "https://myco.auth0.com/"
  oidc_client_id = "client"
  oidc_client_secret = "secret"
  lifecycle {
  ignore_changes = [
     # Ignore changes to oidc_client_secret inside the tests
     "oidc_client_secret"
    ]
  }
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_jwt_auth_backend.jwt.path
  role_name = "%s"
  role_type = "oidc"
  allowed_redirect_uris = ["http://localhost:8080"]

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"
  token_bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  user_claim = "https://vault/user"
  groups_claim = "https://vault/groups"
  token_policies = ["default", "dev", "prod"]
  token_ttl = 3600
  token_num_uses = 12
  token_max_ttl = 7200
  bound_claims_type = "string"
  bound_claims = {
    department = "engineering,admin"
    sector = "7g"
  }
  claim_mappings = {
    preferred_language = "language",
    group = "group"
  }

  verbose_oidc_logging = true
  user_claim_json_pointer = true
  max_age = 120
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfigOIDC_disableParsing(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  type = "oidc"
  path = "%s"
  oidc_discovery_url = "https://myco.auth0.com/"
  oidc_client_id = "client"
  oidc_client_secret = "secret"
  lifecycle {
  ignore_changes = [
     # Ignore changes to oidc_client_secret inside the tests
     "oidc_client_secret"
    ]
  }
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_jwt_auth_backend.jwt.path
  role_name = "%s"
  role_type = "jwt"

  user_claim = "https://vault/user"
  token_policies = ["default", "dev", "prod"]
  bound_claims_type = "string"
  bound_claims = {
    department = "engineering,admin"
    sector = "7g"
  }
  disable_bound_claims_parsing = true
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_fullUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = vault_auth_backend.jwt.path
  role_name = "%s"
  role_type = "jwt"

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"
  token_bound_cidrs = ["10.150.0.0/20", "10.152.0.0/20"]
  bound_audiences = ["https://myco.update",]
  user_claim = "https://vault/updateuser"
  groups_claim = "https://vault/updategroups"
  token_policies = ["default", "dev"]
  token_ttl = 7200
  token_num_uses = 24
  token_max_ttl = 10800
  bound_claims_type = "glob"
  bound_claims = {
    department = "engineering-*-admin"
    sector = "7g"
  }
  user_claim_json_pointer = false
}`, backend, role)
}
