// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestTerraformCloudSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	token := os.Getenv("TEST_TF_TOKEN")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_initialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_updateConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io/not"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/not/api/v2/"),
				),
			},
		},
	})
}

func TestTerraformCloudSecretBackend_remount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	updatedBackend := acctest.RandomWithPrefix("tf-test-terraform-cloud-updated")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_initialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_initialConfig(updatedBackend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", updatedBackend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "token", "disable_remount"),
		},
	})
}

func testTerraformCloudSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  token = "%s"
}`, path, token)
}

func testTerraformCloudSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  address = "https://app.terraform.io/not"
  token = "%s"
  base_path = "/not/api/v2/"
}`, path, token)
}
