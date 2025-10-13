// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")

	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
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
					resource.TestCheckResourceAttr(resourceName, "ttl", "7200"),
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
					resource.TestCheckResourceAttr(resourceName, "ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "86400"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !(meta.IsAPISupported(provider.VaultVersion117) && meta.IsEnterpriseSupported()), nil
				},
				Config: testGCPSecretBackend_WIFConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountEmail, "test"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldDisableRemount,
				consts.FieldCredentials,
				consts.FieldTTL,
				consts.FieldMaxTTL,
			),
		},
	})
}

func TestGCPSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	updatedPath := acctest.RandomWithPrefix("tf-test-gcp-updated")

	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
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
					resource.TestCheckResourceAttr(resourceName, "ttl", "7200"),
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
					resource.TestCheckResourceAttr(resourceName, "ttl", "7200"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "credentials", "disable_remount", consts.FieldTTL),
		},
	})
}

// TestAccGCPSecretBackend_automatedRotation tests that Automated
// Root Rotation parameters are compatible with the GCP Secrets Backend
// resource
func TestAccGCPSecretBackend_automatedRotation(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGCPSecretBackendConfig_automatedRotation(path, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// zero-out rotation_period
			{
				Config: testAccGCPSecretBackendConfig_automatedRotation(path, "*/20 * * * *", 0, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config:      testAccGCPSecretBackendConfig_automatedRotation(path, "", 30, 120, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window
			{
				Config: testAccGCPSecretBackendConfig_automatedRotation(path, "", 30, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

// TestAccKVSecretV2_data_json_wo ensures write-only attribute
// `credentials_wo` works as expected
//
// Since we cannot read the credentials value back from Vault
// there is no way of actually confirming that it is updated.
// Hence, we ensure that the `credentials_wo_version` parameter
// gets updated appropriately.
func TestGCPSecretBackend_credentials_wo(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")

	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_credentialsWO(path, "test", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "credentials_wo_version", "1"),
				),
			},
			{
				Config: testGCPSecretBackend_credentialsWO(path, "test-updated", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "credentials_wo_version", "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldDisableRemount,
				consts.FieldCredentialsWO,
				consts.FieldCredentialsWOVersion,
			),
		},
	})
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
  ttl = 7200
}`, path)
}

func testGCPSecretBackend_WIFConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path                    = "%s"
  service_account_email   = "test"
  identity_token_audience = "test"
  identity_token_ttl      = 30
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
  ttl = 3600
  max_ttl = 86400
  local = true
}`, path)
}

func testAccGCPSecretBackendConfig_automatedRotation(path, schedule string, period, window int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t
}`, path, period, schedule, window, disable)
}

func testGCPSecretBackend_credentialsWO(path, value string, version int) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials_wo = <<EOF
{
  "hello": "%s"
}
EOF
  credentials_wo_version = %d
}`, path, value, version)
}
