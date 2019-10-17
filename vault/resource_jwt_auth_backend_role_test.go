package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccJWTAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"token_bound_cidrs.1709552943", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.2478800941", "https://myco.test"),
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
			{
				ResourceName:      "vault_jwt_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccJWTAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"bound_audiences.2478800941", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"bound_audiences.2478800941", "https://myco.test"),
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"bound_audiences.2478800941", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"token_bound_cidrs.1709552943", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.2478800941", "https://myco.test"),
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
	backend := acctest.RandomWithPrefix("oidc")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"token_bound_cidrs.1709552943", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.2478800941", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/groups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"allowed_redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"allowed_redirect_uris.4240710842", "http://localhost:8080"),
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
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"token_bound_cidrs.1709552943", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.2478800941", "https://myco.test"),
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
						"token_policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_policies.326271447", "dev"),
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
						"token_bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"token_bound_cidrs.520705167", "10.152.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.510103575", "https://myco.update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/updateuser"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/updategroups"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"clock_skew_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"expiration_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"not_before_leeway", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"verbose_oidc_logging", "false"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackendRole_fullDeprecated(t *testing.T) {
	backend := acctest.RandomWithPrefix("jwt")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckJWTAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendRoleConfig_fullDeprecated(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"ttl", "3600"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"num_uses", "12"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.1709552943", "10.148.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.2478800941", "https://myco.test"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/user"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/groups"),
				),
			},
			{
				Config: testAccJWTAuthBackendRoleConfig_fullUpdateDeprecated(backend, role),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"ttl", "7200"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_ttl", "10800"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"num_uses", "24"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.838827017", "10.150.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.520705167", "10.152.0.0/20"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_subject", "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_audiences.510103575", "https://myco.update"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"user_claim", "https://vault/updateuser"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim", "https://vault/updategroups"),
				),
			},
		},
	})
}

func testAccCheckJWTAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_jwt_auth_backend_role" {
			continue
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
  backend = "${vault_auth_backend.jwt.path}"
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
  backend = "${vault_auth_backend.jwt.path}"
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
  backend = "${vault_auth_backend.jwt.path}"
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
     # Ignore changes to odic_clie_secret inside the tests
     "oidc_client_secret"
    ]
  }
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = "${vault_jwt_auth_backend.jwt.path}"
  role_name = "%s"
  role_type = "oidc"
  allowed_redirect_uris = ["http://localhost:8080"]

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"
  token_bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  groups_claim = "https://vault/groups"
  token_policies = ["default", "dev", "prod"]
  token_ttl = 3600
  token_num_uses = 12
  token_max_ttl = 7200
  bound_claims = {
    department = "engineering,admin"
    sector = "7g"
  }
  claim_mappings = {
    preferred_language = "language",
    group = "group"
  }

  verbose_oidc_logging = true
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_fullUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = "${vault_auth_backend.jwt.path}"
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
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_fullDeprecated(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = "${vault_auth_backend.jwt.path}"
  role_name = "%s"
  role_type = "jwt"

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"
  bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  groups_claim = "https://vault/groups"
  policies = ["default", "dev", "prod"]
  ttl = 3600
  num_uses = 12
  max_ttl = 7200
}`, backend, role)
}

func testAccJWTAuthBackendRoleConfig_fullUpdateDeprecated(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "jwt" {
  type = "jwt"
  path = "%s"
}

resource "vault_jwt_auth_backend_role" "role" {
  backend = "${vault_auth_backend.jwt.path}"
	role_name = "%s"
	role_type = "jwt"

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"
  bound_cidrs = ["10.150.0.0/20", "10.152.0.0/20"]
  bound_audiences = ["https://myco.update",]
  user_claim = "https://vault/updateuser"
  groups_claim = "https://vault/updategroups"
  policies = ["default", "dev"]
  ttl = 7200
  num_uses = 24
  max_ttl = 10800
}`, backend, role)
}
