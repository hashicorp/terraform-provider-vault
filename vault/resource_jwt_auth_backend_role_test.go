package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
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
						"period", "0"),
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
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"num_uses", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.#", "0"),
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
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.232240223", "prod"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.#", "0"),
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
						"policies.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.1971754988", "default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"policies.326271447", "dev"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"num_uses", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"period", "0"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"bound_cidrs.#", "0"),
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
						"period", "0"),
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
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim_delimiter_pattern", "/"),
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
						"period", "0"),
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
					resource.TestCheckResourceAttr("vault_jwt_auth_backend_role.role",
						"groups_claim_delimiter_pattern", "/"),
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
						"period", "0"),
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

  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  policies = ["default", "dev", "prod"]
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

  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  policies = ["default", "dev"]
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

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@client"
  bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  bound_audiences = ["https://myco.test"]
  user_claim = "https://vault/user"
  groups_claim = "https://vault/groups"
  groups_claim_delimiter_pattern = "/"
  policies = ["default", "dev", "prod"]
  ttl = 3600
  num_uses = 12
  max_ttl = 7200
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

  bound_subject = "sl29dlldsfj3uECzsU3Sbmh0F29Fios1@update"
  bound_cidrs = ["10.150.0.0/20", "10.152.0.0/20"]
  bound_audiences = ["https://myco.update",]
  user_claim = "https://vault/updateuser"
  groups_claim = "https://vault/updategroups"
  groups_claim_delimiter_pattern = "/"
  policies = ["default", "dev"]
  ttl = 7200
  num_uses = 24
  max_ttl = 10800
}`, backend, role)
}
