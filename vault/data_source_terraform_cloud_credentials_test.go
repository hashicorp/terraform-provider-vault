package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccDataSourceTerraformCloudAccessCredentialsOrganizationClientBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TF_TOKEN")
	organization := os.Getenv("TF_ORGANIZATION")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || organization == "" {
				t.Skipf("TF_TOKEN and TF_ORGANIZATION must be set. Are currently %s and %s respectively", token, organization)
			}
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceTerraformCloudAccessCredentialsOrgConfig(backend, token, name, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token_id"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "organization"),
				),
			},
		},
	})
}

func TestAccDataSourceTerraformCloudAccessCredentialsTeamClientBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TF_TOKEN")
	organization := os.Getenv("TF_ORGANIZATION")
	teamId := os.Getenv("TF_TEAM_ID")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || organization == "" || teamId == "" {
				t.Skipf("TF_TOKEN, TF_ORGANIZATION, and TF_TEAM_ID must be set. Are currently %s, %s and %s respectively", token, organization, teamId)
			}
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceTerraformCloudAccessCredentialsTeamConfig(backend, token, name, organization, teamId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token_id"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "organization"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "team_id"),
				),
			},
		},
	})
}

func TestAccDataSourceTerraformCloudAccessCredentialsUserBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := os.Getenv("TF_TOKEN")
	userId := os.Getenv("TF_USER_ID")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if token == "" || userId == "" {
				t.Skipf("TF_TOKEN and TF_USER_ID must be set. Are currently %s and %s respectively", token, userId)
			}
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceTerraformCloudAccessCredentialsUserConfig(backend, token, name, userId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_access_token.token", "token_id"),
				),
			},
		},
	})
}

func testAccDataSourceTerraformCloudAccessCredentialsOrgConfig(backend, token, name, organization string) string {
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

data "vault_terraform_cloud_access_token" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, organization)
}

func testAccDataSourceTerraformCloudAccessCredentialsTeamConfig(backend, token, name, organization, teamId string) string {
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
  team_id = "%s"
}

data "vault_terraform_cloud_access_token" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, organization, teamId)
}

func testAccDataSourceTerraformCloudAccessCredentialsUserConfig(backend, token, name, userId string) string {
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

data "vault_terraform_cloud_access_token" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, userId)
}
