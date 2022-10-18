package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")

	resourceName := "vault_gcp_secret_backend.test"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccGCPSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testGCPSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"how\":\"goes\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "true"),
				),
			},
		},
	})
}

func TestGCPSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	updatedPath := acctest.RandomWithPrefix("tf-test-gcp-updated")

	resourceName := "vault_gcp_secret_backend.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testGCPSecretBackend_initialConfig(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "credentials", "disable_remount"),
		},
	})
}

func testAccGCPSecretBackendCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_backend" {
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
			if mount.Type == "gcp" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testGCPSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "hello": "world"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 3600
}`, path)
}

func testGCPSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "how": "goes"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  local = true
}`, path)
}
