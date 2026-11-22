// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataTerraformCloudCredentialsOrganizationBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_ORGANIZATION")
	token, organization := vals[0], vals[1]

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataTerraformCloudCredentialsOrgConfig(backend, token, name, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token_id"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "organization"),
				),
			},
		},
	})
}

func TestAccDataTerraformCloudSecretCredentialsTeamBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_ORGANIZATION", "TEST_TF_TEAM_ID")
	token, organization, teamID := vals[0], vals[1], vals[2]

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataTerraformCloudCredentialsTeamConfig(backend, token, name, organization, teamID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token_id"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "organization"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "team_id"),
				),
			},
		},
	})
}

func TestAccDataTerraformCloudCredentialsUserBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_USER_ID")
	token, userID := vals[0], vals[1]

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataTerraformCloudCredentialsUserConfig(backend, token, name, userID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token"),
					resource.TestCheckResourceAttrSet("data.vault_terraform_cloud_credentials.token", "token_id"),
				),
			},
		},
	})
}

func testAccDataTerraformCloudCredentialsOrgConfig(backend, token, name, organization string) string {
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

data "vault_terraform_cloud_credentials" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, organization)
}

func testAccDataTerraformCloudCredentialsTeamConfig(backend, token, name, organization, teamId string) string {
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

data "vault_terraform_cloud_credentials" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, teamId, organization)
}

func testAccDataTerraformCloudCredentialsUserConfig(backend, token, name, userId string) string {
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

data "vault_terraform_cloud_credentials" "token" {
  backend = vault_terraform_cloud_secret_backend.test.backend
  role    = vault_terraform_cloud_secret_role.test.name
}
`, backend, token, name, userId)
}
