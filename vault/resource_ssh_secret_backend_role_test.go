package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccSSHSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "name", name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "backend", backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_bare_domains", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_host_certificates", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_subdomains", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_certificates", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_key_ids", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_critical_options", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_domains", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_extensions", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_extensions.%", "0"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_critical_options.%", "0"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_users", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_user", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_id_format", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_type", "ca"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "ttl", "0"),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_updated(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "name", name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "backend", backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_bare_domains", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_host_certificates", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_subdomains", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_certificates", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_key_ids", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_critical_options", "foo,bar"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_domains", "example.com,foo.com"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_extensions", "ext1,ext2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_extensions.ext1", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_critical_options.opt1", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_users", "usr1,usr2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_user", "usr"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_id_format", "{{role_name}}-test"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_type", "ca"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "max_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "ttl", "43200"),
				),
			},
		},
	})
}

func TestAccSSHSecretBackendRoleOTP_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleOTPConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "name", name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "backend", backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_users", "usr1,usr2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_user", "usr"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "cidr_list", "0.0.0.0/0"),
				),
			},
		},
	})
}

func TestAccSSHSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_updated(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "name", name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "backend", backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_bare_domains", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_host_certificates", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_subdomains", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_certificates", "false"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allow_user_key_ids", "true"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_critical_options", "foo,bar"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_domains", "example.com,foo.com"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_extensions", "ext1,ext2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_extensions.ext1", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_critical_options.opt1", ""),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_users", "usr1,usr2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_user", "usr"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_id_format", "{{role_name}}-test"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "key_type", "ca"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "max_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "ttl", "43200"),
				),
			},
			{
				ResourceName:      "vault_ssh_secret_backend_role.test_role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccSSHSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ssh_secret_backend_role" {
			continue
		}
		role, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if role != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccSSHSecretBackendRoleConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
	name                    = "%s"
	backend                 = "${vault_mount.example.path}"
	key_type                = "ca"
	allow_user_certificates = true
}

`, path, name)
}

func testAccSSHSecretBackendRoleConfig_updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
	name                     = "%s"
	backend                  = "${vault_mount.example.path}"
	allow_bare_domains       = true
	allow_host_certificates  = true
	allow_subdomains         = true
	allow_user_certificates  = false
	allow_user_key_ids       = true
	allowed_critical_options = "foo,bar"
	allowed_domains          = "example.com,foo.com"
	allowed_extensions       = "ext1,ext2"
	default_extensions       = { "ext1" = "" }
	default_critical_options = { "opt1" = "" }
	allowed_users            = "usr1,usr2"
	default_user             = "usr"
	key_id_format            = "{{role_name}}-test"
	key_type                 = "ca"
	max_ttl                  = "86400"
	ttl                      = "43200"
}
`, path, name)
}

func testAccSSHSecretBackendRoleOTPConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
	name                     = "%s"
	backend                  = "${vault_mount.example.path}"
	allowed_users            = "usr1,usr2"
	default_user             = "usr"
	key_type                 = "otp"
	cidr_list                = "0.0.0.0/0"
}
`, path, name)
}
