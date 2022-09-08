package vault

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	consulhelper "github.com/hashicorp/vault/helper/testhelpers/consul"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestConsulSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourceName := "vault_consul_secret_backend.test"
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key"),
			{
				Config: testConsulSecretBackend_initialConfigLocal(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key"),
			{
				Config: testConsulSecretBackend_updateConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key"),
			{
				Config: testConsulSecretBackend_updateConfig_addCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_cert", "FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_key", "FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key"),
			{
				Config: testConsulSecretBackend_updateConfig_updateCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_cert", "UPDATED-FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_key", "UPDATED-FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key"),
		},
	})
}

func TestConsulSecretBackend_Bootstrap(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourceName := "vault_consul_secret_backend.test"
	resourceRoleName := "vault_consul_secret_backend_role.test"

	if !testutil.CheckTestVaultVersion(t, "1.11") {
		t.Skipf("test requires Vault 1.11 or newer")
	}

	cleanup, consulConfig := consulhelper.PrepareTestContainer(t, "1.12.3", false, false)
	t.Cleanup(cleanup)
	consulAddr := consulConfig.Address()

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testConsulSecretBackend_bootstrapConfig(path, consulAddr, "", false),
				ExpectError: regexp.MustCompile("field 'bootstrap' must be set to true when 'token' is unspecified"),
			},
			{
				Config:      testConsulSecretBackend_bootstrapConfig(path, consulAddr, "token", true),
				ExpectError: regexp.MustCompile("field 'bootstrap' must be set to false when 'token' is specified"),
			},
			{
				Config: testConsulSecretBackend_bootstrapConfig(path, consulAddr, "", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", consulAddr),
					resource.TestCheckResourceAttr(resourceName, "bootstrap", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "token", "bootstrap"),
			{
				Config: testConsulSecretBackend_bootstrapAddRole(path, consulAddr),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldName, "management"),
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceRoleName, "consul_policies.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceRoleName, "consul_policies.*", "global-management"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "token", "bootstrap"),
			{
				Config:      testConsulSecretBackend_bootstrapConfig(path+"-new", consulAddr, "", true),
				ExpectError: regexp.MustCompile(`Token not provided and failed to bootstrap ACLs`),
			},
		},
	})
}

func TestConsulSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	updatedPath := acctest.RandomWithPrefix("tf-test-consul-updated")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resourceName := "vault_consul_secret_backend.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
				),
			},
			{
				Config: testConsulSecretBackend_initialConfig(updatedPath, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
				),
			},
			{
				ResourceName:      "vault_consul_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"bootstrap",
					"token",
				},
			},
		},
	})
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

func testConsulSecretBackend_bootstrapConfig(path, addr, token string, bootstrap bool) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "%s"
  token = "%s"
  bootstrap = %t
}
`, path, addr, token, bootstrap)
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

func testConsulSecretBackend_bootstrapAddRole(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "%s"
  bootstrap = true
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
