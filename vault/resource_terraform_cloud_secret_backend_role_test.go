package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestTerraformCloudSecretBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-backend")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TF_TOKEN")
	teamId := os.Getenv("TF_TEAM_ID")
	userId := os.Getenv("TF_USER_ID")
	organization := "hashicorp-vault-testing"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccTerraformCloudSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackendRole_initialConfig(backend, token, name, organization, teamId, userId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "name", name),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "organization", organization),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "ttl", "0"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "max_ttl", "0"),
				),
			},
			{
				Config: testTerraformCloudSecretBackendRole_updateConfig(backend, token, name, organization, teamId, userId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "name", name),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "organization", organization),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "ttl", "120"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend_role.test_org", "max_ttl", "240"),
				),
			},
		},
	})
}

func testAccTerraformCloudSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_terraform_cloud_secret_backend_role" {
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

func testTerraformCloudSecretBackendRole_initialConfig(backend, token, name, organization, teamId, userId string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  path = "%s"
  description = "test description"
  token = "%s"
}

resource "vault_terraform_cloud_secret_backend_role" "test_org" {
  backend = vault_terraform_cloud_secret_backend.test.path
  name = "%s"
  organization = "%s"
}

resource "vault_terraform_cloud_secret_backend_role" "test_team" {
  path = vault_terraform_cloud_secret_backend.test.path
  name = "%[3]s_team_id"
  organization = "%[4]s"
  user_id = "%[5]s"
}

resource "vault_terraform_cloud_secret_backend_role" "test_user" {
  path = vault_terraform_cloud_secret_backend.test.path
  name = "%[3]s_user_id"
  organization = "%[4]s"
  user_id = "%[6]s"
}
`, backend, token, name, organization, teamId, userId)
}

func testTerraformCloudSecretBackendRole_updateConfig(backend, token, name, organization, teamId, userId string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "https://app.terraform.io"
  token = "%s"
}

resource "vault_terraform_cloud_secret_backend_role" "test_org" {
  backend = vault_terraform_cloud_secret_backend.test.path
  name = "%s"
  organization = "%s"

  ttl = 120
  max_ttl = 240
}

resource "vault_terraform_cloud_secret_backend_role" "test_team" {
  path = vault_terraform_cloud_secret_backend.test.path
  name = "%[3]s_team_id"
  organization = "%[4]s"
  team_id = "%[5]s"

  ttl = 120
}

resource "vault_terraform_cloud_secret_backend_role" "test_user" {
  path = vault_terraform_cloud_secret_backend.test.path
  name = "%[3]s_user_id"
  organization = "%[4]s"
  user_id = "%[6]s"

  ttl = 120
}
`, backend, token, name, organization, teamId, userId)
}

func TestTerraformCloudSecretBackendRoleNameFromPath(t *testing.T) {
	{
		name, err := terraformCloudSecretBackendRoleNameFromPath("foo/role/bar")
		if err != nil {
			t.Fatalf("error getting name: %v", err)
		}
		if name != "bar" {
			t.Fatalf("expected name 'bar', but got %s", name)
		}
	}

	{
		name, err := terraformCloudSecretBackendRoleNameFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting name but got nil")
		}
		if name != "" {
			t.Fatalf("expected empty name, but got %s", name)
		}
	}
}

func TestTerraformCloudSecretBackendRoleBackendFromPath(t *testing.T) {
	{
		backend, err := terraformCloudSecretBackendRoleBackendFromPath("foo/role/bar")
		if err != nil {
			t.Fatalf("error getting backend: %v", err)
		}
		if backend != "foo" {
			t.Fatalf("expected backend 'foo', but got %s", backend)
		}
	}

	{
		backend, err := terraformCloudSecretBackendRoleBackendFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting backend but got nil")
		}
		if backend != "" {
			t.Fatalf("expected empty backend, but got %s", backend)
		}
	}
}
