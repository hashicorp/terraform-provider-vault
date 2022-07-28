package vault

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestConsulSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourcePath := "vault_consul_secret_backend.test"
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourcePath, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "http"),
					resource.TestCheckResourceAttr(resourcePath, "local", "false"),
					resource.TestCheckNoResourceAttr(resourcePath, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_key"),
				),
			},
			{
				Config: testConsulSecretBackend_initialConfigLocal(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourcePath, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "http"),
					resource.TestCheckResourceAttr(resourcePath, "local", "true"),
					resource.TestCheckNoResourceAttr(resourcePath, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_key"),
				),
			},
			{
				Config: testConsulSecretBackend_updateConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "https"),
					resource.TestCheckResourceAttr(resourcePath, "local", "false"),
					resource.TestCheckNoResourceAttr(resourcePath, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_cert"),
					resource.TestCheckNoResourceAttr(resourcePath, "client_key"),
				),
			},
			{
				Config: testConsulSecretBackend_updateConfig_addCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "https"),
					resource.TestCheckResourceAttr(resourcePath, "local", "false"),
					resource.TestCheckResourceAttr(resourcePath, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourcePath, "client_cert", "FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourcePath, "client_key", "FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
			{
				Config: testConsulSecretBackend_updateConfig_updateCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourcePath, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "https"),
					resource.TestCheckResourceAttr(resourcePath, "local", "false"),
					resource.TestCheckResourceAttr(resourcePath, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourcePath, "client_cert", "UPDATED-FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourcePath, "client_key", "UPDATED-FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
		},
	})
}

func TestConsulSecretBackend_Bootstrap(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourcePath := "vault_consul_secret_backend.test"
	bootstrapPath := "vault_consul_secret_backend_role.test"
	consulAddr := testutil.GetTestConsulAddr(t)
	if testutil.CheckTestVaultVersion(t, "1.11") {
		resource.Test(t, resource.TestCase{
			Providers:    testProviders,
			PreCheck:     func() { testutil.TestAccPreCheck(t) },
			CheckDestroy: testAccConsulSecretBackendCheckDestroy,
			Steps: []resource.TestStep{
				{
					Config: testConsulSecretBackend_bootstrapConfig(path, consulAddr, false),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourcePath, "path", path),
						resource.TestCheckResourceAttr(resourcePath, "address", consulAddr),
					),
				},
				{
					Config: testConsulSecretBackend_checkBootstrapConfig(path, consulAddr),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(bootstrapPath, "name", "management"),
						resource.TestCheckResourceAttr(bootstrapPath, "backend", path),
						resource.TestCheckResourceAttr(bootstrapPath, "consul_policies.#", "1"),
						resource.TestCheckTypeSetElemAttr(bootstrapPath, "consul_policies.*", "global-management"),
					),
				},
				{
					Config:      testConsulSecretBackend_bootstrapConfig(path, consulAddr, true),
					ExpectError: regexp.MustCompile(`Token not provided and failed to bootstrap ACLs`),
				},
			},
		})
	}
}

func testAccConsulSecretBackendCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_consul_secret_backend" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		mounts, err := client.Sys().ListMounts()
		if err != nil {
			return err
		}

		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "consul" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testConsulSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}`, path, token)
}

func testConsulSecretBackend_initialConfigLocal(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
  local = true
}`, path, token)
}

func testConsulSecretBackend_bootstrapConfig(path, addr string, double bool) string {
	config := fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "%s"
}`, path, addr)

	if double {
		config += fmt.Sprintf(`
resource "vault_consul_secret_backend" "test2" {
  path = "%s-2"
  description = "test description"
  address = "%s"
}`, path, addr)
	}

	return config
}

func testConsulSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
}`, path, token)
}

func testConsulSecretBackend_checkBootstrapConfig(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "%s"
}

resource "vault_consul_secret_backend_role" "test" {
  backend = vault_consul_secret_backend.test.path
  name = "management"
  consul_policies = ["global-management"]
}`, path, addr)
}

func testConsulSecretBackend_updateConfig_addCerts(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
  ca_cert = "FAKE-CERT-MATERIAL"
  client_cert = "FAKE-CLIENT-CERT-MATERIAL"
  client_key = "FAKE-CLIENT-CERT-KEY-MATERIAL"
}`, path, token)
}

func testConsulSecretBackend_updateConfig_updateCerts(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
  ca_cert = "FAKE-CERT-MATERIAL"
  client_cert = "UPDATED-FAKE-CLIENT-CERT-MATERIAL"
  client_key = "UPDATED-FAKE-CLIENT-CERT-KEY-MATERIAL"
}`, path, token)
}
