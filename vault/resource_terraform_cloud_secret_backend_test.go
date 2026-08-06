// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestTerraformCloudSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
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

func TestTerraformCloudSecretBackend_tokenWO(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_tokenWoInitialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token_wo_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_tokenWoUpdatedConfig(backend, token, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "token_wo_version", "2"),
				),
			},
			{
				Config:      testTerraformCloudSecretBackend_tokenWoNoVersion(backend, 3),
				ExpectError: regexp.MustCompile(`all of.*token_wo,token_wo_version.*must be specified`),
			},
			{
				Config:      testTerraformCloudSecretBackend_tokenWoEmptyString(backend, 4),
				ExpectError: regexp.MustCompile(`token_wo must be provided`),
			},
		},
	})
}

// TestTerraformCloudSecretBackend_automatedRotation tests that the automated
// root token rotation parameters are accepted and round-tripped by the
// Terraform Cloud secret backend resource. Automated rotation relies on the
// Vault Enterprise Rotation Manager.
func TestTerraformCloudSecretBackend_automatedRotation(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN")
	token := vals[0]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 10, 0, 3600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExplicitMaxTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// switch to a schedule-based rotation and zero-out rotation_period
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "*/20 * * * *", 0, 120, 3600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// rotation_window is not compatible with rotation_period
			{
				Config:      testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 30, 120, 3600, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window, disable rotation
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 30, 0, 3600, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldToken, consts.FieldDisableRemount),
		},
	})
}

func testTerraformCloudSecretBackend_automatedRotation(backend, token, schedule string, period, window, explicitMaxTTL int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend                    = "%s"
  token                      = "%s"
  explicit_max_ttl           = "%d"
  rotation_period            = "%d"
  rotation_schedule          = "%s"
  rotation_window            = "%d"
  disable_automated_rotation = %t
}`, backend, token, explicitMaxTTL, period, schedule, window, disable)
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

func testTerraformCloudSecretBackend_tokenWoInitialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  token_wo = "%s"
  token_wo_version = 1
}`, path, token)
}

func testTerraformCloudSecretBackend_tokenWoUpdatedConfig(path, token string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo          = "%s"
  token_wo_version  = %d
}`, path, token, version)
}

func testTerraformCloudSecretBackend_tokenWoNoVersion(path string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo_version  = %d
}`, path, version)
}

func testTerraformCloudSecretBackend_tokenWoEmptyString(path string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo          = ""
  token_wo_version  = %d
}`, path, version)
}
