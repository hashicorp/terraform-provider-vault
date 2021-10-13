package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccResourceTerraformCloudSecretCredsOrganizationBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TEST_TF_TOKEN")
	organization := os.Getenv("TEST_TF_ORGANIZATION")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || organization == "" {
				t.Skipf("TEST_TF_TOKEN and TEST_TF_ORGANIZATION must be set. Are currently %s and %s respectively", token, organization)
			}
		},
		CheckDestroy: testAccResourceTerraformCloudSecretCredsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTerraformCloudSecretCredsOrgConfig(backend, token, name, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token_id"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "organization"),
				),
			},
		},
	})
}

func TestAccResourceTerraformCloudSecretCredsTeamBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TEST_TF_TOKEN")
	organization := os.Getenv("TEST_TF_ORGANIZATION")
	teamId := os.Getenv("TEST_TF_TEAM_ID")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || organization == "" || teamId == "" {
				t.Skipf("TEST_TF_TOKEN, TEST_TF_ORGANIZATION, and TEST_TF_TEAM_ID must be set. Are currently %s, %s and %s respectively", token, organization, teamId)
			}
		},
		CheckDestroy: testAccResourceTerraformCloudSecretCredsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTerraformCloudSecretCredsTeamConfig(backend, token, name, organization, teamId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token_id"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "organization"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "team_id"),
				),
			},
		},
	})
}

func TestAccResourceTerraformCloudSecretCredsUserBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TEST_TF_TOKEN")
	userId := os.Getenv("TEST_TF_USER_ID")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || userId == "" {
				t.Skipf("TEST_TF_TOKEN and TEST_TF_USER_ID must be set. Are currently %s and %s respectively", token, userId)
			}
		},
		CheckDestroy: testAccResourceTerraformCloudSecretCredsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTerraformCloudSecretCredsUserConfig(backend, token, name, userId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token"),
					resource.TestCheckResourceAttrSet("vault_terraform_cloud_secret_creds.token", "token_id"),
				),
			},
		},
	})
}

func testAccResourceTerraformCloudSecretCredsOrgConfig(backend, token, name, organization string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  token = "%s"
}

resource "vault_terraform_cloud_secret_role" "test" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  name = "%s"
  organization = "%s"
}

resource "vault_terraform_cloud_secret_creds" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, organization)
}

func testAccResourceTerraformCloudSecretCredsTeamConfig(backend, token, name, organization, teamId string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  token = "%s"
}

resource "vault_terraform_cloud_secret_role" "test" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  name = "%s"
  team_id = "%s"
  organization = "%s"
}

resource "vault_terraform_cloud_secret_creds" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, teamId, organization)
}

func testAccResourceTerraformCloudSecretCredsUserConfig(backend, token, name, userId string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  token = "%s"
}

resource "vault_terraform_cloud_secret_role" "test" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  name = "%s"
  user_id = "%s"
}

resource "vault_terraform_cloud_secret_creds" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, userId)
}

func testAccResourceTerraformCloudSecretCredsCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_terraform_cloud_secret_creds" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("creds %q still exists", rs.Primary.ID)
		}
	}
	return nil
}
