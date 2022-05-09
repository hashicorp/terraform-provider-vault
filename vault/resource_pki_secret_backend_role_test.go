package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki")
	name := acctest.RandomWithPrefix("role")
	resourceName := "vault_pki_secret_backend_role.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRoleConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceName, "allow_localhost", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.0", "test.domain"),
					resource.TestCheckResourceAttr(resourceName, "allow_bare_domains", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_subdomains", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_glob_domains", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_any_name", "false"),
					resource.TestCheckResourceAttr(resourceName, "enforce_hostnames", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_ip_sans", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_uri_sans.0", "uri.test.domain"),
					resource.TestCheckResourceAttr(resourceName, "allowed_other_sans.0", "1.2.3.4.5.5;UTF8:test"),
					resource.TestCheckResourceAttr(resourceName, "server_flag", "true"),
					resource.TestCheckResourceAttr(resourceName, "client_flag", "true"),
					resource.TestCheckResourceAttr(resourceName, "code_signing_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "2048"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.0", "DigitalSignature"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.1", "KeyAgreement"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.2", "KeyEncipherment"),
					resource.TestCheckResourceAttr(resourceName, "ext_key_usage.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "use_csr_common_name", "true"),
					resource.TestCheckResourceAttr(resourceName, "use_csr_sans", "true"),
					resource.TestCheckResourceAttr(resourceName, "ou.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "organization.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "country.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "locality.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "province.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "street_address.0", "123 test"),
					resource.TestCheckResourceAttr(resourceName, "postal_code.0", "12345"),
					resource.TestCheckResourceAttr(resourceName, "generate_lease", "false"),
					resource.TestCheckResourceAttr(resourceName, "no_store", "false"),
					resource.TestCheckResourceAttr(resourceName, "require_cn", "true"),
					resource.TestCheckResourceAttr(resourceName, "policy_identifiers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "policy_identifiers.0", "1.2.3.4"),
					resource.TestCheckResourceAttr(resourceName, "basic_constraints_valid_for_non_ca", "false"),
					resource.TestCheckResourceAttr(resourceName, "not_before_duration", "45m"),
				),
			},
			{
				Config: testPkiSecretBackendRoleConfig_updated(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "allow_localhost", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.0", "other.domain"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.1", "{{identity.entity.name}}"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains_template", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_bare_domains", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_subdomains", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_glob_domains", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_any_name", "false"),
					resource.TestCheckResourceAttr(resourceName, "enforce_hostnames", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_ip_sans", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_uri_sans.0", "uri.test.domain"),
					resource.TestCheckResourceAttr(resourceName, "allowed_other_sans.0", "1.2.3.4.5.5;UTF8:test"),
					resource.TestCheckResourceAttr(resourceName, "server_flag", "true"),
					resource.TestCheckResourceAttr(resourceName, "client_flag", "true"),
					resource.TestCheckResourceAttr(resourceName, "code_signing_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "2048"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "email_protection_flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_usage.0", "DigitalSignature"),
					resource.TestCheckResourceAttr(resourceName, "ext_key_usage.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "use_csr_common_name", "true"),
					resource.TestCheckResourceAttr(resourceName, "use_csr_sans", "true"),
					resource.TestCheckResourceAttr(resourceName, "ou.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "organization.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "country.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "locality.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "province.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "street_address.0", "123 test"),
					resource.TestCheckResourceAttr(resourceName, "postal_code.0", "12345"),
					resource.TestCheckResourceAttr(resourceName, "generate_lease", "false"),
					resource.TestCheckResourceAttr(resourceName, "no_store", "false"),
					resource.TestCheckResourceAttr(resourceName, "require_cn", "true"),
					resource.TestCheckResourceAttr(resourceName, "policy_identifiers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "policy_identifiers.0", "1.2.3.4"),
					resource.TestCheckResourceAttr(resourceName, "basic_constraints_valid_for_non_ca", "false"),
					resource.TestCheckResourceAttr(resourceName, "not_before_duration", "45m"),
				),
			},
		},
	})
}

func testPkiSecretBackendRoleConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_mount.pki" ]
  backend = vault_mount.pki.path
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
  allowed_serial_numbers = ["*"]
}`, path, name)
}

func testPkiSecretBackendRoleConfig_updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_mount.pki" ]
  backend = vault_mount.pki.path
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
  allowed_serial_numbers = ["*"]
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
