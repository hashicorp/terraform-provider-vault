package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestPkiSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki")
	name := acctest.RandomWithPrefix("role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRoleConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_localhost", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains.0", "test.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_bare_domains", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_subdomains", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_glob_domains", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_any_name", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "enforce_hostnames", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_ip_sans", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_uri_sans.0", "uri.test.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_other_sans.0", "1.2.3.4.5.5;UTF8:test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "server_flag", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "client_flag", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "code_signing_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_type", "rsa"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_bits", "2048"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.#", "3"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.0", "DigitalSignature"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.1", "KeyAgreement"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.2", "KeyEncipherment"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ext_key_usage.#", "0"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "use_csr_common_name", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "use_csr_sans", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ou.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "organization.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "country.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "locality.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "province.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "street_address.0", "123 test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "postal_code.0", "12345"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "generate_lease", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "no_store", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "require_cn", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "policy_identifiers.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "policy_identifiers.0", "1.2.3.4"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "basic_constraints_valid_for_non_ca", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "not_before_duration", "45m"),
				),
			},
			{
				Config: testPkiSecretBackendRoleConfig_updated(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ttl", "1800"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "max_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_localhost", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains.#", "2"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains.0", "other.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains.1", "{{identity.entity.name}}"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_domains_template", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_bare_domains", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_subdomains", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_glob_domains", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_any_name", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "enforce_hostnames", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allow_ip_sans", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_uri_sans.0", "uri.test.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "allowed_other_sans.0", "1.2.3.4.5.5;UTF8:test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "server_flag", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "client_flag", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "code_signing_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_type", "rsa"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_bits", "2048"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "email_protection_flag", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "key_usage.0", "DigitalSignature"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ext_key_usage.#", "0"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "use_csr_common_name", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "use_csr_sans", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "ou.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "organization.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "country.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "locality.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "province.0", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "street_address.0", "123 test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "postal_code.0", "12345"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "generate_lease", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "no_store", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "require_cn", "true"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "policy_identifiers.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "policy_identifiers.0", "1.2.3.4"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "basic_constraints_valid_for_non_ca", "false"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_role.test", "not_before_duration", "45m"),
				),
			},
		},
	})
}

func testPkiSecretBackendRoleConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "pki" {
  path = "%s"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_pki_secret_backend.pki" ]
  backend = vault_pki_secret_backend.pki.path
  name = "%s"
  ttl = 3600
  max_ttl = 7200
  allow_localhost = true
  allowed_domains = ["test.domain"]
  allow_bare_domains = false
  allow_subdomains = true
  allow_glob_domains = false
  allow_any_name = false
  enforce_hostnames = true
  allow_ip_sans = true
  allowed_uri_sans = ["uri.test.domain"]
  allowed_other_sans = ["1.2.3.4.5.5;UTF8:test"]
  server_flag = true
  client_flag = true
  code_signing_flag = false
  email_protection_flag = false
  key_type = "rsa"
  key_bits = 2048
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
  ext_key_usage = []
  use_csr_common_name = true
  use_csr_sans = true
  ou = ["test"]
  organization = ["test"]
  country = ["test"]
  locality = ["test"]
  province = ["test"]
  street_address = ["123 test"]
  postal_code = ["12345"]
  generate_lease = false
  no_store = false
  require_cn = true
  policy_identifiers = ["1.2.3.4"]
  basic_constraints_valid_for_non_ca = false
  not_before_duration = "45m"
}`, path, name)
}

func testPkiSecretBackendRoleConfig_updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "pki" {
  path = "%s"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_pki_secret_backend.pki" ]
  backend = vault_pki_secret_backend.pki.path
  name = "%s"
  ttl = 1800
  max_ttl = 3600
  allow_localhost = true
  allowed_domains = ["other.domain", "{{identity.entity.name}}"]
  allowed_domains_template = true
  allow_bare_domains = false
  allow_subdomains = true
  allow_glob_domains = false
  allow_any_name = false
  enforce_hostnames = true
  allow_ip_sans = true
  allowed_uri_sans = ["uri.test.domain"]
  allowed_other_sans = ["1.2.3.4.5.5;UTF8:test"]
  server_flag = true
  client_flag = true
  code_signing_flag = false
  email_protection_flag = false
  key_type = "rsa"
  key_bits = 2048
  key_usage = ["DigitalSignature"]
  ext_key_usage = []
  use_csr_common_name = true
  use_csr_sans = true
  ou = ["test"]
  organization = ["test"]
  country = ["test"]
  locality = ["test"]
  province = ["test"]
  street_address = ["123 test"]
  postal_code = ["12345"]
  generate_lease = false
  no_store = false
  require_cn = true
  policy_identifiers = ["1.2.3.4"]
  basic_constraints_valid_for_non_ca = false
  not_before_duration = "45m"
}`, path, name)
}

func testPkiSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_pki_secret_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}
