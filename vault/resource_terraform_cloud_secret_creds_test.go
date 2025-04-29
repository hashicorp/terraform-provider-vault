// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccResourceTerraformCloudSecretCredsOrganizationBasic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_ORGANIZATION")
	token, organization := vals[0], vals[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_ORGANIZATION", "TEST_TF_TEAM_ID")
	token, organization, teamID := vals[0], vals[1], vals[2]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testAccResourceTerraformCloudSecretCredsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTerraformCloudSecretCredsTeamConfig(backend, token, name, organization, teamID),
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	name := acctest.RandomWithPrefix("tf-test-name")
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_USER_ID")
	token, userID := vals[0], vals[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testAccResourceTerraformCloudSecretCredsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTerraformCloudSecretCredsUserConfig(backend, token, name, userID),
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
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_terraform_cloud_secret_creds" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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
